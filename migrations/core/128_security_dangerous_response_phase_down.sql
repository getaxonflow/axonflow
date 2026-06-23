-- Down Migration 128: revert prompt-injection response-plane evaluation
-- Issue: #2727
-- Reverses 128_security_dangerous_response_phase.sql: restores the four seeded
-- prompt-injection policies (sys_dangerous_injection_*) to request-only
-- evaluation (phase = 'request', action_response = NULL), the state established
-- by migration 116.
--
-- The runner does not auto-apply down migrations; this exists for manual
-- rollback. It is scoped to exactly the policy_ids the up migration touched, so a
-- clean roll-forward/roll-back round-trips and never affects the dangerous-command
-- policies (which the up migration intentionally left request-only).

UPDATE static_policies
SET phase           = 'request',
    action_response = NULL,
    updated_at      = NOW()
WHERE policy_id LIKE 'sys_dangerous_injection_%'
  AND phase = 'both';

DO $$
BEGIN
    RAISE NOTICE 'Migration 128 DOWN: prompt-injection policies reverted to request-only evaluation';
END $$;
