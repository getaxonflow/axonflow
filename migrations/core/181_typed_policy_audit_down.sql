-- Migration 181 DOWN: drop typed_policy_audit
-- Date: 2026-09-12
--
-- ROLL THE BINARIES BACK FIRST. From this migration on, platform/policy/
-- authoringstore writes typed_policy_audit in the same transaction as every
-- artifact insert and every activation append, so a binary that expects the
-- table fails every publish, promote and rollback once it is gone. That is the
-- intended failure mode - a write that cannot be audited does not happen - and
-- it is why the order matters.
--
-- Every audit row goes with the table. The artifacts and activations those
-- rows recorded stay in core/176's tables; what is lost is the record of who
-- published each version, with which approvers, and whether it was
-- self-approved.

BEGIN;

DO $$
DECLARE
    audit_rows INTEGER := 0;
    counted    BOOLEAN := false;
BEGIN
    BEGIN
        SET LOCAL row_security = off;
        IF to_regclass('typed_policy_audit') IS NOT NULL THEN
            EXECUTE 'SELECT COUNT(*) FROM typed_policy_audit' INTO audit_rows;
        END IF;
        counted := true;
    EXCEPTION WHEN OTHERS THEN
        counted := false;
    END;
    SET LOCAL row_security = on;
    IF counted THEN
        RAISE NOTICE 'Migration 181 down: dropping % audit row(s); publish, promote and rollback are no longer audited.', audit_rows;
    ELSE
        RAISE NOTICE 'Migration 181 down: row count UNAVAILABLE (this role cannot read the FORCE-RLS table); dropping every audit row.';
    END IF;
END $$;

DROP TABLE IF EXISTS typed_policy_audit;
DROP FUNCTION IF EXISTS typed_policy_audit_append_only();

DO $$
BEGIN
    IF to_regclass('typed_policy_audit') IS NOT NULL THEN
        RAISE EXCEPTION 'Migration 181 down failed: typed_policy_audit still exists';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc WHERE proname = 'typed_policy_audit_append_only') THEN
        RAISE EXCEPTION 'Migration 181 down failed: typed_policy_audit_append_only() still exists';
    END IF;
    RAISE NOTICE 'Migration 181 down verified: typed_policy_audit and its trigger function are gone.';
END $$;

COMMIT;
