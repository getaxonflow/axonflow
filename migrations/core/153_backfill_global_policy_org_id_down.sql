-- Migration 153 DOWN: revert org_id='global' backfill on global policy rows
-- Issue: #3039
--
-- Restores the pre-153 shape (org_id NULL on tenant_id='global' rows seeded
-- by migrations). Rows seeded by the Go-side seedSystemMediaPolicies carried
-- org_id='global' BEFORE 153; this down cannot distinguish them perfectly,
-- so it reverts only rows whose policy_id matches the migration-seeded
-- 'sys_*' prefix convention while EXCLUDING the Go seeder's 'sys_media_*'
-- rows (which pre-date 153 with org_id='global').

BEGIN;

UPDATE dynamic_policies
    SET org_id = NULL
    WHERE tenant_id = 'global'
      AND org_id = 'global'
      AND policy_id LIKE 'sys\_dyn\_%' ESCAPE '\';

UPDATE static_policies
    SET org_id = NULL
    WHERE tenant_id = 'global'
      AND org_id = 'global'
      AND policy_id LIKE 'sys\_%' ESCAPE '\'
      AND policy_id NOT LIKE 'sys\_media\_%' ESCAPE '\';

COMMIT;
