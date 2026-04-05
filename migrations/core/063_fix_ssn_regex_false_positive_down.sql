-- Rollback: restore optional separator SSN pattern
UPDATE policies SET pattern = '\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
WHERE name = 'pii_ssn_detection'
  AND pattern = '\b\d{3}[-\s]\d{2}[-\s]\d{4}\b';
