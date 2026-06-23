-- Migration 128: Evaluate indirect prompt-injection on the response/tool-output plane
-- Date: 2026-06-23
-- Issue: #2727 (child of epic #2716)
-- Purpose: Make the seeded indirect prompt-injection system policies (migration
--          116: instruction-override, role-reassignment, system-prompt
--          exfiltration, template/bracket markers) apply on the RESPONSE phase
--          too, so a malicious instruction returned in a tool/connector free-text
--          field (e.g. a CRM back-office note) is governed when it re-enters the
--          model's context (a design-partner R&C policy pack section 5.1, risk
--          R03, OWASP LLM01).
--
-- Root cause: migration 116 seeds the four sys_dangerous_injection_* policies with
-- phase = 'request' and action_response = NULL. The shared policy loader
-- (platform/shared/policy/loader.go) loads response-phase policies with
-- `phase IN ('response', 'both')`, so they never reach evaluateOutputPolicies
-- (platform/agent/mcp_handler.go). The response plane today covers SQLi +
-- PII(response) + sensitive-data(response) but NOT prompt-injection, so an
-- injection string in returned data was evaluated on input only.
--
-- SCOPE: ONLY the prompt-injection patterns (policy_id LIKE 'sys_dangerous_injection_%').
-- The other security-dangerous policies (migration 059: dangerous shell commands,
-- SSRF, path traversal, credential-file access, dynamic code-exec) are INTENTIONALLY
-- left request-only. Those patterns describe a command the AGENT is asked to RUN;
-- matching them against connector OUTPUT (e.g. '/etc/passwd' in documentation,
-- 'localhost:8080' in a health response, 'eval(' in a code-review note) would hard-
-- block legitimate data with a high false-positive rate. Indirect prompt-injection
-- is the response-plane threat (it manipulates the model when re-injected); the
-- command patterns are not. They stay on the request plane where they belong.
--
-- This migration flips phase 'request' -> 'both' for the injection policies and
-- sets action_response = 'redact' (previously NULL).
--
-- ACTION on the response plane is REDACT by default, NOT block: the matched
-- injection span is stripped from the tool output (LoI "prompt-injection
-- sanitization") so it never reaches the model, while the legitimate surrounding
-- data passes through. Blocking the whole response on any injection-shaped
-- substring (e.g. a markdown '### System' header, a '[SYSTEM]' log line, an XML
-- '<system>' tag, or a CRM note quoting "ignore previous instructions" as data)
-- would discard legitimate connector output. action_request stays 'block' (an
-- injection instruction in the user's INPUT is still blocked).
--
-- NOTE on enforcement: the runtime response-phase action is resolved by
-- evaluateOutputPolicies (platform/agent/mcp_handler.go) to REDACT by default,
-- overridable per-(org, dangerous_command) via the detection-posture override
-- (#2581/#2609) to warn/block/redact. The action_response column set here is the
-- honest stored/displayed default (mirrors migration 124's philosophy); the
-- behavior change comes from the injection policies now being LOADED and EVALUATED
-- on the response plane at all.
--
-- IDEMPOTENT: the WHERE matches nothing on re-run (rows are already 'both').

UPDATE static_policies
SET phase           = 'both',
    action_response = 'redact',
    updated_at      = NOW()
WHERE policy_id LIKE 'sys_dangerous_injection_%'
  AND phase = 'request';

-- Fail-loud verification: every prompt-injection row is now response-evaluable,
-- and the dangerous-command patterns (059) remain request-only (no new
-- false-positive surface on the response plane).
DO $$
DECLARE
    stale_injection INTEGER;
    promoted_command INTEGER;
BEGIN
    SELECT COUNT(*) INTO stale_injection
    FROM static_policies
    WHERE policy_id LIKE 'sys_dangerous_injection_%'
      AND phase = 'request';
    IF stale_injection > 0 THEN
        RAISE WARNING 'Migration 128: % prompt-injection rows still request-only (no response-plane coverage)', stale_injection;
    END IF;

    SELECT COUNT(*) INTO promoted_command
    FROM static_policies
    WHERE category LIKE 'security-dangerous%'
      AND policy_id NOT LIKE 'sys_dangerous_injection_%'
      AND phase <> 'request';
    IF promoted_command > 0 THEN
        RAISE WARNING 'Migration 128: % dangerous-command rows are NOT request-only (unexpected response-plane exposure)', promoted_command;
    END IF;

    IF stale_injection = 0 AND promoted_command = 0 THEN
        RAISE NOTICE 'Migration 128 verified: prompt-injection evaluates on the response plane; dangerous-command patterns stay request-only';
    END IF;
END $$;
