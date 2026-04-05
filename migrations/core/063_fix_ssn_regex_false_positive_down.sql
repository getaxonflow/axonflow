-- Rollback: restore original PII patterns

UPDATE static_policies SET pattern = '\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b'
WHERE policy_id = 'sys_pii_ssn'
  AND pattern = '\b(\d{3})[- ](\d{2})[- ](\d{4})\b';

UPDATE static_policies SET pattern = '\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
WHERE policy_id = 'pii_ssn_detection'
  AND pattern = '\b\d{3}[- ]\d{2}[- ]\d{4}\b';

UPDATE static_policies SET pattern = '(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b|\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b'
WHERE policy_id = 'sys_pii_phone'
  AND pattern NOT LIKE '%[-.]%';
