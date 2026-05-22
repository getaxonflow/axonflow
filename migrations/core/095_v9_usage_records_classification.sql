-- Migration 095: v9 usage_records.team_id classification (docs-only)
-- Date: 2026-05-19
--
-- usage_records.team_id is an ATTRIBUTION-TAG class column, NOT part of the
-- v9 identity model. It belongs to a future team/workspace/cost-center
-- feature, not the org_id/client_id/user_id triad. Recording the
-- classification on-record via COMMENT prevents future migrations from
-- accidentally folding team_id into v9 identity.
--
-- This migration is doc-only — no schema change. usage_records.org_id +
-- tenant_id (already present in the table since 034) ARE part of the v9
-- identity model and are handled by 094's Pass-2 deployment-org backfill
-- on read paths once the write-path fix lands.
--
-- Idempotency: COMMENT is overwrite-safe; re-running is a no-op.
-- Rollback: _down.sql restores the pre-095 COMMENT state (which was empty).
--
-- Depends on: 034_cost_controls

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'usage_records') THEN
        EXECUTE 'COMMENT ON COLUMN usage_records.team_id IS ''ATTRIBUTION TAG (not part of the v9 identity model). Cost/budget grouping inside an org — orthogonal to org_id/client_id/user_id. Do NOT migrate team_id into the v9 identity model — design a separate team/workspace feature if/when product needs it.''';

        EXECUTE 'COMMENT ON COLUMN usage_records.org_id IS ''Customer/account identity column. Populated by request handlers; backfilled via 094 Pass-2 deployment-org fallback for historical rows.''';

        EXECUTE 'COMMENT ON COLUMN usage_records.tenant_id IS ''Credential alias (deprecated). Equivalent to client_id; tracked as a compatibility column until a future major version drops it.''';

        RAISE NOTICE 'Migration 095: usage_records column classifications recorded';
    ELSE
        RAISE NOTICE 'Migration 095: usage_records missing — skipping';
    END IF;
END $$;
