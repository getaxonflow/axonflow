-- Migration 173 DOWN: remove the five sys_media_* governance policies
-- Date: 2026-09-08
-- Purpose: Reverse migrations/core/173_seed_system_media_policies.sql.
-- Related: #3786
--
-- WHAT THIS REMOVES, AND WHY THAT IS THE CORRECT REVERSAL EVEN THOUGH THE ROWS
-- MAY PREDATE THE MIGRATION
--
-- On a stack where the orchestrator's Go seeder already created these rows, the
-- up migration's INSERT was a no-op - ON CONFLICT DO NOTHING - so this down
-- deletes rows the up did not create. That is deliberate and it is the only
-- coherent choice: the two writers are idempotent on the same five identifiers
-- and the database records no provenance distinguishing them, so a down that
-- tried to delete "only what the up inserted" would have to guess.
--
-- The cost of guessing wrong in the other direction is worse. A down that
-- deleted nothing would leave the five rows behind on a fresh stack where this
-- migration IS the only thing that created them, and the schema would not
-- return to its pre-173 state.
--
-- The rows are re-creatable either way: re-applying 173, or the orchestrator's
-- own seeder on the next boot of a stack whose application role can still
-- write (i.e. one where migrations/core/172 has also been rolled back).
--
-- WHY THERE IS NO row_security SETTING
--
-- dynamic_policies is ENABLE (not FORCE) ROW LEVEL SECURITY (core/018), and a
-- migration runs as the table OWNER, for whom an un-FORCEd policy does not
-- apply. The DELETE below therefore reaches every row without any setting.
--
-- An earlier version turned row_security off and justified it with "the DELETE
-- would remove nothing" - measurably false for the owner. And the setting is
-- not the remedy it looks like: for a role that IS bound it does not bypass
-- RLS, it converts the affected statement into `ERROR: query would be affected
-- by row-level security policy` (42501), which enterprise/142's down migration
-- already records. So it would be a no-op here and a hard failure exactly
-- where it appeared to help.
--
-- REVISIT WHEN dynamic_policies gains FORCE ROW LEVEL SECURITY: the owner is
-- bound from that day, this DELETE stops matching, and the verification below
-- fails loudly rather than silently leaving the rows.

BEGIN;

DO $$
DECLARE
    n INTEGER;
BEGIN
    SELECT COUNT(*) INTO n FROM dynamic_policies
    WHERE policy_id IN ('sys_media_nsfw_block', 'sys_media_violence_warn',
                        'sys_media_biometric_log', 'sys_media_pii_block',
                        'sys_media_sensitive_doc_warn');
    RAISE NOTICE 'Migration 173 down: removing % system media governance policy row(s).', n;
END $$;

DELETE FROM dynamic_policies
WHERE policy_id IN ('sys_media_nsfw_block', 'sys_media_violence_warn',
                    'sys_media_biometric_log', 'sys_media_pii_block',
                    'sys_media_sensitive_doc_warn')
  AND tier = 'system'
  AND org_id = 'global';

DO $$
DECLARE
    n INTEGER;
BEGIN
    SELECT COUNT(*) INTO n FROM dynamic_policies
    WHERE policy_id IN ('sys_media_nsfw_block', 'sys_media_violence_warn',
                        'sys_media_biometric_log', 'sys_media_pii_block',
                        'sys_media_sensitive_doc_warn');
    IF n <> 0 THEN
        RAISE EXCEPTION 'Migration 173 down failed: % system media policy row(s) remain', n;
    END IF;
    RAISE NOTICE 'Migration 173 down verified: no system media governance policies remain.';
END $$;

COMMIT;
