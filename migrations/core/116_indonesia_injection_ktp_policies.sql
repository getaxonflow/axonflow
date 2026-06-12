-- Migration 116: Indirect prompt-injection + KTP system policies (#2522)
-- Date: 2026-06-05
-- Purpose: Seed the security-dangerous prompt-injection patterns and the
--          Indonesia KTP detection menu entry into static_policies so they are
--          enforced by the shared policy engine (Gateway Mode pre-check) and
--          surface in the policy menu.
-- Related: Issue #2522 (a design partner's R&C policy pack), epic #2518.
--
-- This migration is the canonical source for these system policies (migrations
-- are the single source of truth for system-tier policies — #2696). The
-- runtime KTP BLOCK decision is made by the Enterprise Indonesia PII detector
-- (ee/platform/agent/indonesia), which additionally validates the digit-
-- normalized core as a real NIK; this row provides the menu/spec parity and
-- the Community-edition shared-engine regex fallback.
--
-- Cross-edition: indirect prompt-injection (R&C §5.1, risk R03, OWASP LLM01)
-- applies to all editions, so these live in migrations/core/ alongside the
-- pre-existing security-dangerous patterns from migration 059.
--
-- Idempotent: INSERT ... ON CONFLICT (policy_id) DO NOTHING. No CREATE POLICY /
-- TRIGGER, so re-running on an existing deployment is a no-op.

-- Indirect Prompt Injection (security-dangerous, 4 patterns)
-- RE2-safe (no backreferences/lookarounds), scoped to instruction-like language.
INSERT INTO static_policies (policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by, phase, action_request, action_response)
VALUES
  ('sys_dangerous_injection_override', 'Prompt Injection — Instruction Override', 'security-dangerous', 'system',
   '(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)*(?:(?:previous|prior|above|earlier|preceding|initial|system|original)\s+(?:instruction|instructions|prompt|prompts|directive|directives|rule|rules|guardrail|guardrails)|(?:instruction|instructions|prompt|prompts|directive|directives|guardrail|guardrails))\b',
   'high', 'Detects attempts to ignore/override prior instructions, prompts, or guardrails in free-text (R&C §5.1, R03, OWASP LLM01)',
   'block', 95, true, 'global', 'system', 'request', 'block', NULL),
  ('sys_dangerous_injection_role_override', 'Prompt Injection — Role Reassignment', 'security-dangerous', 'system',
   '(?i)(?:\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\s+(?:an?\s+|the\s+)?(?:admin|administrator|root|superuser|system\s+administrator|unrestricted|jailbroken|jailbreak|dan\s+mode|developer\s+mode|do\s+anything\s+now|a\s+different\s+(?:ai|model|assistant))\b|\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must)\b)',
   'high', 'Detects attempts to reassign the assistant role to a privileged/jailbreak persona',
   'block', 95, true, 'global', 'system', 'request', 'block', NULL),
  ('sys_dangerous_injection_system_exfil', 'Prompt Injection — System Prompt Exfiltration', 'security-dangerous', 'system',
   '(?i)\b(?:reveal|show|print|repeat|display|output|leak|expose)\b[^.\n]{0,30}\b(?:system\s+prompt|your\s+(?:instructions|prompt|rules|system)|initial\s+(?:prompt|instructions)|the\s+prompt\s+above)\b',
   'high', 'Detects attempts to reveal/print/repeat the system prompt or hidden instructions',
   'block', 95, true, 'global', 'system', 'request', 'block', NULL),
  ('sys_dangerous_injection_bracket_marker', 'Prompt Injection — Template/Bracket Marker', 'security-dangerous', 'system',
   '(?i)(?:\[\s*(?:system|assistant|inst|/inst|user)\s*\]|<\s*(?:system|im_start|im_end)\s*>|###\s*(?:system|instruction)\b|<\|(?:im_start|im_end|system)\|>)',
   'high', 'Detects injected chat-template or role-delimiter markers ([system], <im_start>, ### system)',
   'block', 95, true, 'global', 'system', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- Indonesia KTP (pii-indonesia, 1 pattern) — menu/spec parity. Runtime BLOCK is
-- made by the Enterprise Indonesia PII detector with NIK validation.
-- NOTE: keep the `description` text below free of apostrophes — it is a
-- single-quoted SQL literal, so an unescaped ' terminates the string and
-- crashes this migration at run time (#2544 regression guard).
INSERT INTO static_policies (policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by, phase, action_request, action_response)
VALUES
  ('sys_pii_indonesia_ktp', 'Indonesian KTP Detection', 'pii-indonesia', 'system',
   '(?i)(?:no[\s._-]*ktp|nomor[\s_-]*ktp|kartu[\s_-]*tanda[\s_-]*penduduk|ktp)(?:[\s:#=]+(?:no\.?|nomor|number|num|adalah|is))*[\s:#=]*[0-9][0-9.\s-]{14,22}[0-9]',
   'critical', 'Indonesian KTP (national ID card) number — keyword-anchored, catches separator-formatted and word-bridged KTP/NIK ("KTP number is 3201-…") (UU PDP Art. 4, OJK POJK 11/2022; design-partner R&C §4.1)',
   'block', 100, true, 'global', 'system', 'request', 'block', NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- Verified: migrations 1..116 apply cleanly in order (no SQL-literal parse
-- error in the description above) — see the #2544 apostrophe regression guard.
