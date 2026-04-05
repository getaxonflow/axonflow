-- Migration 063: Fix PII regex false positives on timestamps
-- Date: 2026-04-05
--
-- 1. SSN: \b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b matched 123456789 (separators optional).
--    Fix: require separator. SSN is always XXX-XX-XXXX or XXX XX XXXX.
--
-- 2. Legacy SSN (pii_ssn_detection from migration 010): same issue.
--
-- 3. Phone: [-.\s]? matched dots in timestamps (58.1234 → 3 digits + dot + 4 digits).
--    Fix: remove dot from phone separator — phones use dashes/spaces, not dots.

-- Fix sys_pii_ssn (migration 031)
UPDATE static_policies SET pattern = '\b(\d{3})[- ](\d{2})[- ](\d{4})\b'
WHERE policy_id = 'sys_pii_ssn'
  AND pattern = '\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b';

-- Fix pii_ssn_detection (migration 010)
UPDATE static_policies SET pattern = '\b\d{3}[- ]\d{2}[- ]\d{4}\b'
WHERE policy_id = 'pii_ssn_detection'
  AND pattern = '\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b';

-- Fix sys_pii_phone: remove dot from separator (prevents matching decimals in timestamps)
UPDATE static_policies SET pattern = '(?:\+?1[-\s]?)?(?:\(?[0-9]{3}\)?[-\s]?)?[0-9]{3}[-\s]?[0-9]{4}\b|\+[0-9]{1,3}[-\s]?[0-9]{6,14}\b'
WHERE policy_id = 'sys_pii_phone'
  AND pattern LIKE '%[-.\\s]%';
