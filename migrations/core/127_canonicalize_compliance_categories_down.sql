-- Down Migration 127: revert compliance policy category canonicalisation
-- Issue: #2728
-- Reverses 127_canonicalize_compliance_categories.sql: restores the drifted
-- category spelling on the seeded (tenant_id = 'global') compliance policies
-- and recreates the dependent reporting views / indexes with the drifted
-- literal so they match again.
--
-- The runner does not auto-apply down migrations; this exists for manual
-- rollback. The UPDATEs are scoped to tenant_id = 'global' (the scope the
-- compliance seeds insert under) so a manual rollback reverses exactly the
-- seed canonicalisation and never clobbers an independently canonical row.

-- ============================================================================
-- 1. Restore the drifted category on the seeded compliance policies
-- ============================================================================
UPDATE static_policies SET category = 'eu_ai_act_compliance', updated_at = NOW()
    WHERE category = 'compliance-euaiact' AND tenant_id = 'global';

UPDATE static_policies SET category = 'rbi_compliance', updated_at = NOW()
    WHERE category = 'compliance-rbi' AND tenant_id = 'global';

UPDATE static_policies SET category = 'sebi_compliance', updated_at = NOW()
    WHERE category = 'compliance-sebi' AND tenant_id = 'global';

UPDATE static_policies SET category = 'mas_feat_compliance', updated_at = NOW()
    WHERE category = 'compliance-masfeat' AND tenant_id = 'global';

-- ============================================================================
-- 2. Restore the EU AI Act reporting objects (core/014, every mode)
-- ============================================================================
DROP INDEX IF EXISTS idx_static_policies_eu_compliance;
CREATE INDEX IF NOT EXISTS idx_static_policies_eu_compliance
ON static_policies(category)
WHERE category = 'eu_ai_act_compliance' AND enabled = true;

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
WHERE category = 'eu_ai_act_compliance'
   OR (metadata->>'eu_ai_act_article') IS NOT NULL
ORDER BY metadata->>'eu_ai_act_article';

-- ============================================================================
-- 3. Restore the industry reporting objects only where they exist
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
            WHERE category IN ('sebi_compliance', 'pii_detection')
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
            WHERE category = 'sebi_compliance'
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
            WHERE sp.category IN ('sebi_compliance', 'pii_detection')
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
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_indexes
               WHERE schemaname = 'public'
                 AND indexname = 'idx_static_policies_rbi_compliance') THEN
        EXECUTE 'DROP INDEX IF EXISTS idx_static_policies_rbi_compliance';
        EXECUTE $idx$
            CREATE INDEX idx_static_policies_rbi_compliance
            ON static_policies(category, enabled)
            WHERE category IN ('rbi_compliance', 'pii_detection')
        $idx$;
    END IF;
END $$;

-- MAS FEAT (industry/banking/401) ----------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_indexes
               WHERE schemaname = 'public'
                 AND indexname = 'idx_static_policies_mas_feat_compliance') THEN
        EXECUTE 'DROP INDEX IF EXISTS idx_static_policies_mas_feat_compliance';
        EXECUTE $idx$
            CREATE INDEX idx_static_policies_mas_feat_compliance
            ON static_policies(category, enabled)
            WHERE category IN ('mas_feat_compliance', 'pii_detection')
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
            WHERE category = 'mas_feat_compliance'
               OR (
                   category = 'pii_detection'
                   AND (metadata->>'compliance_framework') LIKE '%MAS%'
               )
            ORDER BY metadata->>'mas_pillar', severity DESC
        $vw$;
    END IF;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 127 DOWN: compliance policy categories reverted to drifted spelling';
END $$;
