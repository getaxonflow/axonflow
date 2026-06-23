-- Migration 127: Canonicalize drifted compliance policy categories
-- Date: 2026-06-23
-- Issue: #2728 (child of epic #2716)
-- Purpose: Make the seeded RBI / SEBI / MAS-FEAT / EU-AI-Act compliance
--          policies actually fire on /decide and the gateway.
--
-- Root cause: the compliance seed migrations stored static_policies.category
-- using a non-canonical spelling that does NOT match the canonical constants
-- in platform/shared/policy/types.go:
--
--     seeded (drifted)          canonical constant (types.go)
--     ----------------          -----------------------------
--     eu_ai_act_compliance  ->  compliance-euaiact
--     rbi_compliance        ->  compliance-rbi
--     sebi_compliance       ->  compliance-sebi
--     mas_feat_compliance   ->  compliance-masfeat
--
-- The decide/gateway category filter (platform/shared/policy/engine.go
-- filterByCategories) and IsComplianceCategory (types.go) are EXACT-match on
-- the canonical PolicyCategory, so the drifted rows were silently excluded
-- whenever a compliance category was requested and were never recognised as
-- compliance policies. Caught live during a design-partner PoC (#2717).
--
-- Two populations are repaired:
--   1. EXISTING deployments that already ran the drifted seeds: the four
--      UPDATEs below rewrite the stored category, and the dependent reporting
--      views / partial indexes are recreated so they keep matching their rows.
--   2. FRESH deployments: the INDUSTRY seed source migrations were
--      canonicalised at source in this same PR (industry/travel/200,
--      industry/banking/300, /302, /401). The migration runner applies core/
--      BEFORE industry/ (global version sort, see migration_helpers.go), so a
--      forward UPDATE here cannot reach a fresh industry seed that has not run
--      yet -- which is exactly why the industry seeds were fixed at source.
--      The EU-AI-Act seed (core/014) is deliberately LEFT drifted at source and
--      forward-fixed by the UPDATE below instead, because core/014 sorts before
--      core/127 and so is reachable (the idiomatic forward-fix used by e.g.
--      core/124). On a fresh deploy core/014 inserts drifted rows, then this
--      migration rewrites them and recreates the EU index/view canonically.
--
-- Note: static_policies.category is VARCHAR(50) with NO CHECK constraint
-- (core/010), so no constraint has to be widened.
--
-- Depends: 010_policy_tables (static_policies, policy_violations),
--          014_eu_ai_act_templates (eu_ai_act_compliance_summary view + index)

-- ============================================================================
-- 1. Canonicalise the stored category on every drifted row (all tiers / tenants)
-- ============================================================================
UPDATE static_policies SET category = 'compliance-euaiact', updated_at = NOW()
    WHERE category = 'eu_ai_act_compliance';

UPDATE static_policies SET category = 'compliance-rbi', updated_at = NOW()
    WHERE category = 'rbi_compliance';

UPDATE static_policies SET category = 'compliance-sebi', updated_at = NOW()
    WHERE category = 'sebi_compliance';

UPDATE static_policies SET category = 'compliance-masfeat', updated_at = NOW()
    WHERE category = 'mas_feat_compliance';

-- ============================================================================
-- 2. Recreate the EU AI Act reporting objects (core/014 -> present in EVERY
--    deployment mode, so recreate unconditionally).
-- ============================================================================
DROP INDEX IF EXISTS idx_static_policies_eu_compliance;
CREATE INDEX IF NOT EXISTS idx_static_policies_eu_compliance
ON static_policies(category)
WHERE category = 'compliance-euaiact' AND enabled = true;

CREATE OR REPLACE VIEW eu_ai_act_compliance_summary AS
SELECT
    policy_id,
    name,
    metadata->>'eu_ai_act_article' as article,
    metadata->>'article_name' as article_name,
    metadata->>'compliance_framework' as framework,
    severity,
    action,
    enabled,
    created_at,
    updated_at
FROM static_policies
WHERE category = 'compliance-euaiact'
   OR (metadata->>'eu_ai_act_article') IS NOT NULL
ORDER BY metadata->>'eu_ai_act_article';

-- ============================================================================
-- 3. Recreate the industry reporting objects ONLY where they already exist
--    (industry/banking/* runs in saas + in-vpc-banking only). On a fresh
--    industry deploy these do not exist yet when core/127 runs; the
--    canonicalised seed migrations recreate them later. On an existing
--    industry deploy the guarded blocks repair the drifted definitions so the
--    views keep returning the now-canonical rows.
-- ============================================================================

-- SEBI (industry/banking/300) --------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_indexes
               WHERE schemaname = 'public'
                 AND indexname = 'idx_static_policies_sebi_compliance') THEN
        EXECUTE 'DROP INDEX IF EXISTS idx_static_policies_sebi_compliance';
        EXECUTE $idx$
            CREATE INDEX idx_static_policies_sebi_compliance
            ON static_policies(category, enabled)
            WHERE category IN ('compliance-sebi', 'pii_detection')
        $idx$;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.views
               WHERE table_schema = 'public'
                 AND table_name = 'sebi_compliance_summary') THEN
        EXECUTE $vw$
            CREATE OR REPLACE VIEW sebi_compliance_summary AS
            SELECT
                policy_id,
                name,
                tenant_id,
                metadata->>'sebi_requirement' as requirement,
                metadata->>'sebi_pillar' as pillar,
                metadata->>'compliance_framework' as framework,
                severity,
                action,
                enabled,
                COALESCE((metadata->>'audit_retention_years')::integer, 5) as retention_years,
                created_at,
                updated_at
            FROM static_policies
            WHERE category = 'compliance-sebi'
               OR (
                   category = 'pii_detection'
                   AND (
                       (metadata->>'compliance_framework') LIKE '%SEBI%'
                       OR (metadata->>'compliance_framework') LIKE '%DPDP%'
                   )
               )
            ORDER BY metadata->>'sebi_pillar', severity DESC
        $vw$;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.views
               WHERE table_schema = 'public'
                 AND table_name = 'sebi_audit_retention_status') THEN
        EXECUTE $vw$
            CREATE OR REPLACE VIEW sebi_audit_retention_status AS
            SELECT
                sp.policy_id,
                sp.name,
                sp.tenant_id,
                COALESCE((sp.metadata->>'audit_retention_years')::integer, 5) as required_retention_years,
                COUNT(pv.id) as total_violations,
                MIN(pv.created_at) as oldest_violation,
                MAX(pv.created_at) as newest_violation,
                CASE
                    WHEN COUNT(pv.id) = 0 THEN 'NO_VIOLATIONS'
                    WHEN MIN(pv.created_at) > NOW() - INTERVAL '5 years' THEN 'COMPLIANT'
                    ELSE 'REVIEW_REQUIRED'
                END as retention_status
            FROM static_policies sp
            LEFT JOIN policy_violations pv ON pv.violation_type = sp.policy_id
            WHERE sp.category IN ('compliance-sebi', 'pii_detection')
              AND (
                  (sp.metadata->>'compliance_framework') LIKE '%SEBI%'
                  OR (sp.metadata->>'compliance_framework') LIKE '%DPDP%'
              )
            GROUP BY sp.policy_id, sp.name, sp.tenant_id, (sp.metadata->>'audit_retention_years')
            ORDER BY sp.policy_id
        $vw$;
    END IF;
END $$;

-- RBI (industry/banking/302) ---------------------------------------------------
-- The two RBI reporting views filter on metadata (rbi_framework /
-- compliance_framework), not on the category literal, so they survive the
-- canonicalisation unchanged. Only the partial index references the literal.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_indexes
               WHERE schemaname = 'public'
                 AND indexname = 'idx_static_policies_rbi_compliance') THEN
        EXECUTE 'DROP INDEX IF EXISTS idx_static_policies_rbi_compliance';
        EXECUTE $idx$
            CREATE INDEX idx_static_policies_rbi_compliance
            ON static_policies(category, enabled)
            WHERE category IN ('compliance-rbi', 'pii_detection')
        $idx$;
    END IF;
END $$;

-- MAS FEAT (industry/banking/401) ----------------------------------------------
-- The pillar-coverage and audit-retention views filter on metadata, not the
-- category literal, so only mas_feat_compliance_summary and the partial index
-- reference the drifted string.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_indexes
               WHERE schemaname = 'public'
                 AND indexname = 'idx_static_policies_mas_feat_compliance') THEN
        EXECUTE 'DROP INDEX IF EXISTS idx_static_policies_mas_feat_compliance';
        EXECUTE $idx$
            CREATE INDEX idx_static_policies_mas_feat_compliance
            ON static_policies(category, enabled)
            WHERE category IN ('compliance-masfeat', 'pii_detection')
        $idx$;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.views
               WHERE table_schema = 'public'
                 AND table_name = 'mas_feat_compliance_summary') THEN
        EXECUTE $vw$
            CREATE OR REPLACE VIEW mas_feat_compliance_summary AS
            SELECT
                policy_id,
                name,
                tenant_id,
                metadata->>'mas_requirement' as requirement,
                metadata->>'mas_pillar' as pillar,
                metadata->>'mas_use_case' as use_case,
                metadata->>'materiality' as materiality,
                metadata->>'compliance_framework' as framework,
                severity,
                action,
                enabled,
                COALESCE((metadata->>'audit_retention_years')::integer, 7) as retention_years,
                COALESCE((metadata->>'human_oversight_required')::boolean, false) as human_oversight_required,
                created_at,
                updated_at
            FROM static_policies
            WHERE category = 'compliance-masfeat'
               OR (
                   category = 'pii_detection'
                   AND (metadata->>'compliance_framework') LIKE '%MAS%'
               )
            ORDER BY metadata->>'mas_pillar', severity DESC
        $vw$;
    END IF;
END $$;

-- ============================================================================
-- Success message
-- ============================================================================
DO $$
DECLARE
    drifted_remaining INTEGER;
    canonical_total INTEGER;
BEGIN
    SELECT COUNT(*) INTO drifted_remaining FROM static_policies
        WHERE category IN ('eu_ai_act_compliance', 'rbi_compliance',
                           'sebi_compliance', 'mas_feat_compliance');
    SELECT COUNT(*) INTO canonical_total FROM static_policies
        WHERE category IN ('compliance-euaiact', 'compliance-rbi',
                           'compliance-sebi', 'compliance-masfeat');
    RAISE NOTICE 'Migration 127: compliance policy categories canonicalised';
    RAISE NOTICE '  - drifted rows remaining (want 0): %', drifted_remaining;
    RAISE NOTICE '  - canonical compliance rows now:   %', canonical_total;
END $$;
