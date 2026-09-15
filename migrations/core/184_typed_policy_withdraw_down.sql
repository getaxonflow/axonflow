-- Down for migration 184: new withdrawals are refused again, and the history
-- keeps every withdraw row it already holds.
--
-- The narrow CHECKs come back NOT VALID. A validated CHECK would fail on the
-- first withdraw row the ledger holds, and the ledger is append-only (core/176's
-- triggers refuse UPDATE and DELETE), so the only honest shapes are refusing to
-- go down or keeping the history. NOT VALID keeps it: Postgres enforces the
-- constraint on every new row and does not re-check the rows already there.

BEGIN;

ALTER TABLE typed_policy_activations DROP CONSTRAINT IF EXISTS typed_policy_activations_withdraw_reason_chk;
ALTER TABLE typed_policy_activations DROP CONSTRAINT IF EXISTS typed_policy_activations_kind_chk;
ALTER TABLE typed_policy_activations ADD CONSTRAINT typed_policy_activations_kind_chk
    CHECK (kind IN ('promote', 'rollback')) NOT VALID;

ALTER TABLE typed_policy_audit DROP CONSTRAINT IF EXISTS typed_policy_audit_withdraw_reason_chk;
ALTER TABLE typed_policy_audit DROP CONSTRAINT IF EXISTS typed_policy_audit_action_chk;
ALTER TABLE typed_policy_audit ADD CONSTRAINT typed_policy_audit_action_chk
    CHECK (action IN ('publish', 'promote', 'rollback')) NOT VALID;

COMMIT;
