-- Migration 152 DOWN: deliberately does NOT restore the owner-drift trigger (#3003)
-- Date: 2026-07-22
--
-- The trigger this migration removed is a confirmed privilege-escalation
-- vector: it granted the `owner` system role from a plain
-- `UPDATE organizations SET contact_email = ...`, reachable ANONYMOUSLY through
-- PATCH /api/v1/admin/organizations/{org_id} on a default bundle (ADMIN_API_KEY
-- unset ⇒ admin_auth passes the caller through), and audited only as
-- UPDATE_ORG. Re-creating it on a down-migration would silently re-open that
-- hole on a rollback, so this DOWN is intentionally not a literal inverse.
--
-- Same precedent as migration 148's down (which deliberately does not delete
-- seeded role rows): a down migration must not restore a state that is unsafe.
--
-- The capability the trigger provided is NOT lost — it moved up a layer, to
-- HandleUpdateOrganization, which re-seeds the owner via GrantOrgOwner after a
-- successful contact-email change and emits an ASSIGN_OWNER audit row, behind a
-- strict authenticated-admin check.
--
-- NOTE: rolling the platform binary back does NOT restore the trigger by
-- itself. The migration tracker keys on version + filename, so 149 is already
-- recorded as applied and will not re-run. If you genuinely need the trigger
-- back (you almost certainly do not), re-run the trigger section of
-- migrations/core/149_owner_assignment_backfill_and_bootstrap.sql by hand,
-- having first confirmed ADMIN_API_KEY is set on every portal — otherwise you
-- are re-opening anonymous owner conferral.

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'Migration 152 down: no-op by design — the contact_email owner-drift trigger is NOT restored (#3003 privilege-escalation vector). See the file header.';
END $$;

COMMIT;
