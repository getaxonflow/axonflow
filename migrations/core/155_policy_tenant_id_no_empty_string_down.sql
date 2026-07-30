-- Rollback for migration 155 (#3059).
--
-- Drops the CHECK constraints. The ''→NULL normalization and the
-- accompanying `enabled = false` on dynamic_policies are LEFT IN PLACE
-- deliberately, for two reasons.
--
-- First, '' has no defined semantics — it is the ambiguous shape this
-- migration exists to remove — and no code path can produce it, so restoring
-- it would only re-create the defect.
--
-- Second, and more important: reverting the disable WITHOUT reverting the
-- tenant value would be the dangerous half of the pair. On the database
-- engine a NULL tenant loads as the 'default' apply-to-all sentinel, so
-- re-enabling those rows while they are NULL promotes them from "enforced for
-- nobody" to "enforced for every tenant" — exactly the inversion the up
-- migration disables them to avoid. Down migrations cannot tell which rows
-- they would be re-enabling, so they leave the safe state alone.
--
-- Note the up migration's disable is behavior-preserving on
-- DatabaseDynamicPolicyEngine (what production runs) but DE-ENFORCING on the
-- in-memory fallback DynamicPolicyEngine, where an empty tenant applied to
-- every caller. Rolling this migration back does not restore that fallback
-- behavior either, since the tenant value stays NULL.
--
-- Operators who want such a row live should assign it a real tenant_id and
-- re-enable it deliberately, via direct SQL — a NULL-tenant row is not
-- reachable through the portal or the policy API. The up migration RAISEs the
-- affected policy_ids as a WARNING for exactly that purpose.

BEGIN;

ALTER TABLE IF EXISTS dynamic_policies DROP CONSTRAINT IF EXISTS dynamic_policies_tenant_id_not_empty;
ALTER TABLE IF EXISTS static_policies DROP CONSTRAINT IF EXISTS static_policies_tenant_id_not_empty;

COMMIT;
