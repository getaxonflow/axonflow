-- Migration 063: Tighten SSN regex to require separators
-- Date: 2026-04-05
-- Context: SSN pattern \b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b matched 9-digit timestamps
--          like 123456789 because separators were optional ([-\s]?).
--          Changed to require at least dashes or spaces between groups.
--          SSN format is always XXX-XX-XXXX or XXX XX XXXX — never 9 consecutive digits.

UPDATE static_policies SET pattern = '\b(\d{3})[- ](\d{2})[- ](\d{4})\b'
WHERE policy_id = 'sys_pii_ssn'
  AND pattern = '\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b';
