-- Migration 169 Down: remove trust-realm persistence (#3550, session v10.3-D)
--
-- Drops identity_trust_realms and identity_realm_epochs and everything 169
-- attached to them. Every organization's realms then live only in whatever
-- in-memory RealmRegistry each replica was told about by some other channel,
-- which is the pre-169 (#3556) posture.
--
-- IT NAMES WHAT IT DISCARDS. A row here is an organization's declaration of
-- which identity source it trusts and what credentials from it may assert.
-- Dropping the table forgets every such declaration at once, and a realm that
-- is forgotten is UNKNOWN_REALM rather than a realm with defaults - so every
-- credential from a forgotten issuer is DENIED until the registry is
-- repopulated. That is the safe direction, and it is still an outage, so the
-- NOTICE below counts the realms and the organizations being removed before
-- removing them.
--
-- THE EPOCHS ARE THE OTHER HALF. Dropping identity_realm_epochs resets every
-- organization's identity epoch. A decision proof or a cached closure bound to
-- a pre-rollback epoch will compare against a lower number afterwards, so
-- staleness that WAS detectable stops being. Anything relying on the epoch
-- must be invalidated wholesale after this runs rather than trusted to notice.
--
-- Existence is probed through pg_catalog (to_regclass), never
-- information_schema (#3463). Idempotent: running it against a database that
-- never applied 169 is a no-op with a NOTICE, not an error.

BEGIN;

DO $$
DECLARE
    realms      bigint := 0;
    orgs        bigint := 0;
    disabled    bigint := 0;
    epoch_rows  bigint := 0;
    max_epoch   bigint := 0;
BEGIN
    IF to_regclass('identity_trust_realms') IS NULL
       AND to_regclass('identity_realm_epochs') IS NULL THEN
        RAISE NOTICE 'migration 169 down: identity_trust_realms / identity_realm_epochs do not exist; nothing to remove.';
        RETURN;
    END IF;

    -- The counts are a deployment-wide operator report, so the policy is
    -- lifted for this transaction only. A rollback is by definition
    -- deployment-wide and these numbers go to a log, never into a decision.
    IF to_regclass('identity_trust_realms') IS NOT NULL THEN
        ALTER TABLE identity_trust_realms NO FORCE ROW LEVEL SECURITY;
        SELECT count(*), count(DISTINCT org_id), count(*) FILTER (WHERE NOT enabled)
          INTO realms, orgs, disabled
          FROM identity_trust_realms;
    END IF;
    IF to_regclass('identity_realm_epochs') IS NOT NULL THEN
        ALTER TABLE identity_realm_epochs NO FORCE ROW LEVEL SECURITY;
        SELECT count(*), COALESCE(max(epoch), 0) INTO epoch_rows, max_epoch
          FROM identity_realm_epochs;
    END IF;

    DROP POLICY IF EXISTS identity_trust_realms_org_isolation ON identity_trust_realms;
    DROP POLICY IF EXISTS identity_realm_epochs_org_isolation ON identity_realm_epochs;
    DROP TABLE IF EXISTS identity_trust_realms;
    DROP TABLE IF EXISTS identity_realm_epochs;

    RAISE NOTICE 'migration 169 down: trust-realm persistence removed. Discarded % realm declaration(s) across % organization(s) (% of them administratively disabled); every credential from those issuers is UNKNOWN_REALM and therefore DENIED until each replica''s in-memory registry is repopulated. Also discarded % identity-epoch row(s) (highest was %), so anything bound to a pre-rollback epoch must be invalidated wholesale rather than trusted to detect its own staleness.',
                 realms, orgs, disabled, epoch_rows, max_epoch;
END
$$;

COMMIT;
