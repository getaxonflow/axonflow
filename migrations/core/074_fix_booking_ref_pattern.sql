-- Migration 074: Tighten sys_pii_booking_ref pattern to require a
-- booking-context label.
--
-- The original pattern \b[A-Z0-9]{6}\b matched any 6-char alphanumeric
-- token, including every common SQL keyword (SELECT, INSERT, DELETE,
-- UPDATE, CREATE, RETURN). Action is "log" (not block) so requests
-- weren't failing, but every benign SQL query through the policy
-- engine generated a sys_pii_booking_ref audit-log entry — polluting
-- audit trails, inflating "PII detected" counts in compliance
-- dashboards, and adding noise to the matched_policies field of every
-- API response containing SQL.
--
-- The new pattern requires the alphanumeric token to follow a
-- booking-context label (booking|reservation|reference|ref|pnr|
-- confirmation|conf), so it fires on real booking refs like
-- "booking ABC123" or "PNR XYZ789" but ignores benign SQL keywords.
--
-- Idempotent: the UPDATE is conditional on the OLD pattern still being
-- in place. Stacks that have already been migrated (or hand-edited)
-- are left alone.

UPDATE static_policies
SET pattern = '(?i)\b(?:booking|reservation|reference|ref|pnr|conf(?:irmation)?)\b\s*[:#]?\s*\b([A-Z0-9]{6})\b'
WHERE policy_id = 'sys_pii_booking_ref'
  AND pattern = '\b[A-Z0-9]{6}\b';

-- No data backfill needed — this is a forward-looking pattern change.
-- Audit log entries previously emitted for bare alphanumeric tokens
-- remain in place for historical accuracy.
