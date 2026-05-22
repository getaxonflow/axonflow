-- Migration 090: v9 policy-table client_id columns (additive)
-- Date: 2026-05-19
--
-- Classification (credential class where tenant_id acts as such today):
--   static_policies (010)      — tenant_id DEFAULT 'global'; per-credential
--                                policy scoping with 'global' as v9-compatible
--                                "applies-to-all" sentinel.
--   dynamic_policies (010)     — same treatment.
--   policy_evaluations (039)   — per-evaluation log, tenant_id NOT NULL.
--                                Adds VARCHAR org_id (separate from the
--                                pre-existing UUID-typed organization_id
--                                column which stays for legacy callers).
--
-- The 'global' sentinel is preserved verbatim in client_id when backfilling
-- — a row with tenant_id='global' becomes client_id='global', which keeps
-- the v9 wildcard meaning consistent with the static_policies/dynamic_policies
-- SELECT path (e.g. get_dynamic_policies_for_tenant in migration 010 treats
-- 'global' as "applies to every tenant").
--
-- Idempotency: ADD COLUMN IF NOT EXISTS + WHERE-empty UPDATE + CREATE INDEX
-- IF NOT EXISTS throughout. Re-runs are no-ops.
--
-- Rollback: paired _down.sql drops the new columns + indexes.
--
-- Depends on: 010_policy_tables, 039_mcp_policy_phases

-- ============================================================================
-- static_policies
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policies') THEN
        ALTER TABLE static_policies
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(100);

        UPDATE static_policies
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_static_policies_client
            ON static_policies(client_id) WHERE enabled = true;

        CREATE INDEX IF NOT EXISTS idx_static_policies_org_client
            ON static_policies(org_id, client_id) WHERE enabled = true;

        RAISE NOTICE 'Migration 090: static_policies.client_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 090: static_policies missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- dynamic_policies
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dynamic_policies') THEN
        ALTER TABLE dynamic_policies
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(100);

        UPDATE dynamic_policies
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_dynamic_policies_client
            ON dynamic_policies(client_id) WHERE enabled = true;

        CREATE INDEX IF NOT EXISTS idx_dynamic_policies_org_client
            ON dynamic_policies(org_id, client_id) WHERE enabled = true;

        RAISE NOTICE 'Migration 090: dynamic_policies.client_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 090: dynamic_policies missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- policy_evaluations (per-evaluation log)
-- ============================================================================
-- policy_evaluations has organization_id UUID (legacy) which is NOT the same
-- shape as the VARCHAR(255) org_id used everywhere else. Add a separate
-- VARCHAR org_id column for v9 callers; leave organization_id UUID for
-- backwards compatibility with existing readers. Backfill client_id from
-- tenant_id and add the v9 composite index.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_evaluations') THEN
        ALTER TABLE policy_evaluations
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(100);

        ALTER TABLE policy_evaluations
            ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

        UPDATE policy_evaluations
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_policy_evaluations_client_time
            ON policy_evaluations(client_id, created_at DESC);

        CREATE INDEX IF NOT EXISTS idx_policy_evaluations_org_client_time
            ON policy_evaluations(org_id, client_id, created_at DESC);

        RAISE NOTICE 'Migration 090: policy_evaluations.client_id + org_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 090: policy_evaluations missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- Column documentation
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'static_policies' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN static_policies.client_id IS ''Credential identity column. The ''''global'''' sentinel is preserved verbatim for system-wide policies that apply across all clients.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'dynamic_policies' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN dynamic_policies.client_id IS ''Credential identity column. The ''''global'''' sentinel is preserved verbatim for system-wide policies that apply across all clients.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN policy_evaluations.client_id IS ''Credential identity column. Separate from the legacy organization_id UUID column.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'org_id') THEN
        EXECUTE 'COMMENT ON COLUMN policy_evaluations.org_id IS ''Customer/account identity (VARCHAR). Mirrors org_id shape used in audit_logs/static_policies; coexists with the legacy organization_id UUID column.''';
    END IF;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 090 complete — v9 policy-table client_id additive layer';
END $$;
