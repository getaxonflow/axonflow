-- Migration 184: a withdrawal is an activation kind and an audited action
-- Date: 2026-09-13
-- Purpose: Admit 'withdraw' to typed_policy_activations.kind (core/176) and to
--          typed_policy_audit.action (core/181), each with the reason a
--          withdrawal must carry. An organization can withdraw its typed
--          document and return to the implicit bundle (PRD v11 §1.15): an
--          appended activation that names the shipped organization template's
--          digest and chains onto the document it withdrew. Nothing is deleted.
-- Related: PRD v11 §1.15, #3746 (W3-I item 10), migrations/core/176 and 181,
--          migrations/enterprise/159 (the same change to enterprise/155's copy
--          of the ledger).
--
-- EDITION: COMMUNITY (mirrored). core/176 and core/181 ship on every edition,
-- and a Community organization withdraws like any other.
--
-- IDEMPOTENT: each constraint is dropped IF EXISTS and re-added, so a rerun over
-- a ledger that already holds withdraw rows re-validates them and succeeds. The
-- withdraw-reason constraints are NEW constraints rather than widened rollback
-- ones, so the rollback constraints core/176 and core/181 declared stay exactly
-- as they were and this file's down drops only what it added.

BEGIN;

ALTER TABLE typed_policy_activations DROP CONSTRAINT IF EXISTS typed_policy_activations_kind_chk;
ALTER TABLE typed_policy_activations ADD CONSTRAINT typed_policy_activations_kind_chk
    CHECK (kind IN ('promote', 'rollback', 'withdraw'));

-- A withdrawal records a reason: an unexplained return to the shipped set wants
-- explaining as much as a rollback does.
ALTER TABLE typed_policy_activations DROP CONSTRAINT IF EXISTS typed_policy_activations_withdraw_reason_chk;
ALTER TABLE typed_policy_activations ADD CONSTRAINT typed_policy_activations_withdraw_reason_chk
    CHECK (kind <> 'withdraw' OR reason <> '');

ALTER TABLE typed_policy_audit DROP CONSTRAINT IF EXISTS typed_policy_audit_action_chk;
ALTER TABLE typed_policy_audit ADD CONSTRAINT typed_policy_audit_action_chk
    CHECK (action IN ('publish', 'promote', 'rollback', 'withdraw'));

ALTER TABLE typed_policy_audit DROP CONSTRAINT IF EXISTS typed_policy_audit_withdraw_reason_chk;
ALTER TABLE typed_policy_audit ADD CONSTRAINT typed_policy_audit_withdraw_reason_chk
    CHECK (action <> 'withdraw' OR reason <> '');

-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT, the pattern of core/176 and core/181
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    def TEXT;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_catalog.pg_constraint
    WHERE conname = 'typed_policy_activations_kind_chk';
    IF def IS NULL OR def NOT LIKE '%withdraw%' OR def NOT LIKE '%promote%' OR def NOT LIKE '%rollback%' THEN
        RAISE EXCEPTION 'migration 184 self-verification: typed_policy_activations_kind_chk is %, not promote/rollback/withdraw', COALESCE(def, 'absent');
    END IF;

    SELECT pg_get_constraintdef(oid) INTO def FROM pg_catalog.pg_constraint
    WHERE conname = 'typed_policy_audit_action_chk';
    IF def IS NULL OR def NOT LIKE '%withdraw%' OR def NOT LIKE '%publish%' THEN
        RAISE EXCEPTION 'migration 184 self-verification: typed_policy_audit_action_chk is %, not publish/promote/rollback/withdraw', COALESCE(def, 'absent');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'typed_policy_activations_withdraw_reason_chk')
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'typed_policy_audit_withdraw_reason_chk') THEN
        RAISE EXCEPTION 'migration 184 self-verification: a withdraw-reason constraint is missing';
    END IF;
END $$;

COMMIT;
