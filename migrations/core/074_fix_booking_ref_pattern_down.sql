-- Down migration for 074: revert sys_pii_booking_ref to the original
-- bare \b[A-Z0-9]{6}\b pattern.
--
-- Idempotent: only restores the original if the row currently carries
-- the post-074 pattern.

UPDATE static_policies
SET pattern = '\b[A-Z0-9]{6}\b'
WHERE policy_id = 'sys_pii_booking_ref'
  AND pattern = '(?i)\b(?:booking|reservation|reference|ref|pnr|conf(?:irmation)?)\b\s*[:#]?\s*\b([A-Z0-9]{6})\b';
