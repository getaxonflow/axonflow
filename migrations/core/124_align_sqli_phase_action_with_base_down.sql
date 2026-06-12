-- Down for migration 124: restore the pre-124 'block' phase actions on
-- `security-sqli` system policies.
--
-- This reverses the data alignment only. Enforcement is unchanged either way:
-- the AXONFLOW_PROFILE override (BuildActionOverrides -> engine.go) always wins,
-- so the runtime SQLi action stays 'warn' in the `default` profile whether the
-- phase columns read 'block' (pre-124) or 'warn' (post-124).
--
-- Scope mirrors the up migration: only system-tier security-sqli rows whose base
-- action is 'warn' and whose phase columns the up migration set to 'warn'.

UPDATE static_policies
SET action_request  = 'block',
    action_response = 'block',
    updated_at      = NOW()
WHERE tier = 'system'
  AND category IN ('security-sqli', 'sqli')
  AND action = 'warn'
  AND action_request  = 'warn'
  AND action_response = 'warn';
