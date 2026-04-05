-- Migration 063: Fix PII regex false positives on ISO timestamps
-- Date: 2026-04-05
-- Context: ISO timestamp 10:37:58.123456789Z triggered 4 false positives:
--
-- 1. SSN: \d{3}[-\s]?\d{2}[-\s]?\d{4} matched 123456789 (separators optional).
--    Fix: require separator. SSN is always XXX-XX-XXXX or XXX XX XXXX.
--
-- 2. Legacy SSN (pii_ssn_detection): same issue.
--
-- 3. Phone: [-.\s]? matched dots in timestamps (58.1234 → 3+dot+4 phone pattern).
--    Fix: dots only allowed when all separators are dots (555.123.4567).
--
-- 4. Singapore UEN: \d{8,9}[A-Z] matched 123456789Z (Z = UTC timezone indicator).
--    Fix: exclude Z as trailing letter (UEN uses A-Y check letters, not Z).

-- Fix sys_pii_ssn (migration 031)
UPDATE static_policies SET pattern = '\b(\d{3})[- ](\d{2})[- ](\d{4})\b'
WHERE policy_id = 'sys_pii_ssn'
  AND pattern = '\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b';

-- Fix pii_ssn_detection (migration 010)
UPDATE static_policies SET pattern = '\b\d{3}[- ]\d{2}[- ]\d{4}\b'
WHERE policy_id = 'pii_ssn_detection'
  AND pattern = '\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b';

-- Fix sys_pii_phone: dots only allowed when ALL separators are dots (555.123.4567).
-- Prevents 58.1234 in timestamps from matching as partial phone number.
UPDATE static_policies SET pattern = '(?:\+?1[-\s.]?)?(?:\(?[0-9]{3}\)?[-\s])?[0-9]{3}[-\s][0-9]{4}\b|[0-9]{3}\.[0-9]{3}\.[0-9]{4}\b|\+[0-9]{1,3}[-\s]?[0-9]{6,14}\b'
WHERE policy_id = 'sys_pii_phone';

-- Fix sys_pii_singapore_uen: exclude Z as trailing letter
-- UEN format is 8-9 digits + check letter (A-Y). Z is UTC timezone, not a check letter.
UPDATE static_policies SET pattern = '\b\d{8,9}[A-Y]\b|\b[TS]\d{2}[A-Z]{2}\d{4}[A-Z]\b'
WHERE policy_id = 'sys_pii_singapore_uen'
  AND pattern = '\b\d{8,9}[A-Z]\b|\b[TS]\d{2}[A-Z]{2}\d{4}[A-Z]\b';
