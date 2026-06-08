-- Down migration 116: remove the #2522 prompt-injection + KTP system policies.
DELETE FROM static_policies WHERE policy_id IN (
  'sys_dangerous_injection_override',
  'sys_dangerous_injection_role_override',
  'sys_dangerous_injection_system_exfil',
  'sys_dangerous_injection_bracket_marker',
  'sys_pii_indonesia_ktp'
);
