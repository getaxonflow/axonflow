-- Rollback: restore optional separator SSN pattern
UPDATE static_policies SET pattern = '\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b'
WHERE policy_id = 'sys_pii_ssn'
  AND pattern = '\b(\d{3})[- ](\d{2})[- ](\d{4})\b';
