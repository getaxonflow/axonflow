-- Migration 152: drop the contact_email owner-drift trigger (#3003)
-- Date: 2026-07-22
--
-- SECURITY FIX. Migration 149 installed an AFTER UPDATE OF contact_email
-- trigger (reseed_org_owner_on_contact_change) that grants the `owner` system
-- role to whatever address lands in organizations.contact_email. Its header
-- asserted this "can never be driven by an unprivileged portal session" —
-- true of the router, wrong about the auth bar:
--
--   * The only HTTP writer is PATCH /api/v1/admin/organizations/{org_id}
--     (HandleUpdateOrganization), and that handler had NO requireStrictAdmin.
--   * middleware/admin_auth.go treats auth as OPTIONAL in in-vpc-* /
--     saas-staging when ADMIN_API_KEY is unset — the SHIPPED DEFAULT (the
--     install .env.example ships it blank) — passing the caller through with
--     Authenticated=false, Identifier="anonymous".
--
-- So on a default self-hosted bundle any caller who could reach the portal
-- admin API could confer `owner` on an arbitrary email in ANY org, with
-- source='system' (survives SCIM re-sync), audited only as
-- UPDATE_ORG {"fields_changed":N} — never ASSIGN_OWNER. Under Path B that
-- address then resolves to fleet role `owner` (tenant-wide audit reads +
-- sso:configure), routing around the #2993 anti-escalation gate entirely.
--
-- Beyond the anonymous vector, a DB-level trigger means ANY future or manual
-- `UPDATE organizations SET contact_email = ...` silently mints an owner with
-- no audit trail. That is the wrong layer for a privilege grant.
--
-- Fix (two prongs; this migration is the second):
--   1. HandleUpdateOrganization now requires a strict authenticated admin
--      whenever the request carries contact_email (api/organizations.go).
--   2. This migration drops the trigger; the handler re-seeds the owner
--      explicitly via GrantOrgOwner after a successful contact-email change,
--      which emits a real ASSIGN_OWNER audit row.
--
-- The INSERT-side trigger (seed_org_owner_on_create, mig 149) is UNTOUCHED:
-- org creation is a different, already-authenticated path and its grant is the
-- bootstrap this whole line of work exists to provide.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'organizations'
    ) THEN
        RAISE NOTICE 'Migration 152: organizations does not exist - skipping';
        RETURN;
    END IF;

    DROP TRIGGER IF EXISTS reseed_org_owner_on_contact_change ON organizations;
    DROP FUNCTION IF EXISTS trg_reseed_org_owner_on_contact_change();

    RAISE NOTICE 'Migration 152: contact_email owner-drift trigger dropped (#3003)';
END $$;

-- Verification — the trigger and its function must be gone (Principle 3).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'organizations'
    ) THEN
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'reseed_org_owner_on_contact_change' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'Migration 152 failed: reseed_org_owner_on_contact_change trigger still present';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'trg_reseed_org_owner_on_contact_change') THEN
        RAISE EXCEPTION 'Migration 152 failed: trg_reseed_org_owner_on_contact_change function still present';
    END IF;

    RAISE NOTICE 'Migration 152 verified: owner-drift trigger and function removed';
END $$;

COMMIT;
