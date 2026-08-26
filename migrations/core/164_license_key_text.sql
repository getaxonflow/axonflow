-- Migration 164: organizations.license_key VARCHAR(512) -> TEXT
-- Date: 2026-08-24
-- Issue: #3341 (found by its e2e suite; the defect itself is independent of SAML)
-- Guard decision: no existence guard - organizations.license_key is unconditional in core/002 (which always sorts first), and re-running ALTER ... TYPE TEXT is idempotent.
--
-- THE DEFECT. organizations.license_key (core/002) is VARCHAR(512), but the
-- platform's own keygen mints V2 licence keys whose length grows with the org
-- id, the permission grants and the expiry payload. Measured with the repo's
-- keygen (Enterprise tier, 7 days, the standard six-family permission set):
--
--   org id 'wt3341-nokey-org'  (16 chars) -> key length 512  (fits, by luck)
--   org id 'wt3341-ownkey-org' (17 chars) -> key length 515  (does not fit)
--
-- So /api/v1/admin/onboard-customer answers 500 "Failed to insert into
-- database: pq: value too long for type character varying(512)" for the second
-- org while succeeding for the first, and which side of the cliff a customer
-- lands on depends on the LENGTH OF THEIR ORG NAME. The key passes licence
-- VALIDATION first (admin.go validates before inserting), so the refusal
-- arrives from the storage layer, after the key was proven genuine.
--
-- THE FIX. The column carries an opaque signed token whose length the schema
-- cannot know; TEXT is the honest type. Widening varchar -> text is a
-- metadata-only change in PostgreSQL (no table rewrite, no data change).
--
-- Only this column stores a RAW licence key. The look-alike columns
-- (core/002 api_keys.key_hash, enterprise/101 license_key_hash, ...) store
-- fixed-length hashes and are correct at VARCHAR(512).

BEGIN;

ALTER TABLE organizations ALTER COLUMN license_key TYPE TEXT;

COMMIT;
