-- Migration 155: forbid empty-string tenant_id on policy tables (#3059)
-- Date: 2026-07-28
-- Issue: #3059
--
-- #3059 was a cross-tenant disclosure on GET /api/v1/policies/dynamic. The
-- Go fix scopes the list to the caller. This migration removes the one row
-- shape that makes the tenant column ambiguous in the first place.
--
-- tenant_id has three meaningful values: a real tenant id, 'global' (shared
-- baseline), or NULL (loaded as the 'default' sentinel). Empty string is a
-- fourth, accidental shape with no defined semantics: the orchestrator's
-- cache carries it as _metadata.tenant_id = '', which the evaluator gates
-- to NOBODY, while the pre-fix list returned it to EVERYBODY. Nothing in the
-- current code path can create it — PolicyRepository.Create rejects an empty
-- tenant, both seeders write 'global' or a real tenant, and refreshPolicies
-- maps SQL NULL to 'default' — so it can only arrive from a legacy row or a
-- manual INSERT. The column has neither NOT NULL nor a CHECK today
-- (010_policy_tables.sql), so nothing stops it.
--
-- Two parts, both idempotent:
--   1. Normalize any existing '' rows to NULL (the documented "no tenant"
--      value).
--   2. Add CHECK (tenant_id IS NULL OR tenant_id <> '') so the shape cannot
--      come back, on both policy tables.
--
-- WHY dynamic_policies ROWS ARE ALSO DISABLED (read before changing this):
--
-- On dynamic_policies, normalizing '' to NULL would INVERT enforcement rather
-- than preserve it, so the repair disables those rows in the same statement.
--
--   before: tenant_id = ''   -> refreshPolicies keeps ""      -> the tenant
--           gate (dbCachedPolicyAppliesToTenant) matches no non-empty caller
--           -> enforced for NOBODY.
--   after:  tenant_id = NULL -> refreshPolicies maps to "default"
--           -> "default" is an apply-to-all sentinel
--           -> enforced for EVERY tenant in the deployment.
--
-- Silently promoting a dormant row — possibly carrying a `block` action — to
-- deployment-wide enforcement during a security patch is a production
-- availability event. `enabled = false` prevents that: refreshPolicies selects
-- `WHERE enabled = true`, so a disabled row never enters the gate cache and
-- remains enforced for nobody, which is what tenant_id = '' already meant.
--
-- SCOPE OF "preserves prior behavior": true on DatabaseDynamicPolicyEngine,
-- which is what production runs. It is NOT true on the in-memory fallback
-- DynamicPolicyEngine, where memPolicyAppliesToTenant
-- (platform/orchestrator/dynamic_policy_engine.go) returns
-- `policyTenant == "" || policyTenant == callerTenant` — an empty tenant
-- applies to EVERY caller there. On a deployment that had fallen back, a
-- legacy '' row therefore goes from enforced-for-every-tenant to
-- enforced-for-nobody: a de-enforcement, i.e. the fail-OPEN direction.
-- Compound reachability is negligible (the '' shape is unreachable through
-- any current code path, the fallback must be engaged, and its own DB connect
-- must have succeeded where the database engine's failed), and the
-- alternative — leaving the row enabled — is a fail-CLOSED surprise on the
-- engine production actually uses. Stated here so the trade-off is explicit
-- rather than discovered.
--
-- HOW TO REMEDIATE. The row is NOT reachable through the portal or the policy
-- API: PolicyRepository.GetByID filters
-- `(tenant_id = $2 OR tenant_id = 'global')` and List fills `tenant_id = $1`
-- per scope with the caller's tenant or 'global'
-- (platform/orchestrator/policy_api_repository.go), and a NULL tenant matches
-- neither — NULL = $n evaluates to NULL, not true. So a UI round-trip is not
-- available. Remediation is direct SQL against the policy_ids named in the
-- WARNING below: assign a real tenant_id and set enabled = true in one
-- statement.
--
-- Two incidental effects of the UPDATE, neither of which changes which
-- policies are enforced: the update_dynamic_policies_updated_at trigger
-- (migrations/core/010) bumps updated_at, and
-- trg_dynamic_policies_critical_no_override (migrations/core/070) coerces
-- allow_override to FALSE if the row is critical-risk.
--
-- static_policies is NOT disabled, because there the normalization is a true
-- no-op: the loader selects `(tenant_id = $1 OR tenant_id = 'global')`
-- (platform/shared/policy/loader.go), and both '' and NULL fail that predicate
-- for every caller — NULL = $1 evaluates to NULL, not true. Those rows are
-- dormant before and after, so disabling them would be a gratuitous change.
--
-- Additive and reversible. No table rewrite: the CHECK is added on tables
-- whose rows are normalized first, so validation is a scan, not a rewrite.

BEGIN;

-- Part 1: normalize existing empty-string tenants to NULL.
DO $$
DECLARE
    rows_updated INTEGER;
    affected_ids TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'tenant_id') THEN
        -- Capture the ids BEFORE the update: afterwards the predicate no
        -- longer matches and the operator would have no way to find them.
        SELECT string_agg(policy_id, ', ' ORDER BY policy_id)
          INTO affected_ids
          FROM dynamic_policies
         WHERE tenant_id = '';

        -- enabled = false is deliberate and load-bearing — see the header.
        -- NULL alone would flip these rows from "enforced for nobody" to
        -- "enforced for every tenant".
        UPDATE dynamic_policies
           SET tenant_id = NULL,
               enabled    = false
         WHERE tenant_id = '';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        IF rows_updated > 0 THEN
            RAISE WARNING 'Migration 155: % dynamic_policies row(s) had tenant_id='''' (a shape enforced for NO tenant). Normalized to NULL and DISABLED so they do not silently become enforced deployment-wide. Re-enable deliberately after assigning a real tenant_id. Affected policy_id(s): %',
                rows_updated, affected_ids;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id') THEN
        SELECT string_agg(policy_id, ', ' ORDER BY policy_id)
          INTO affected_ids
          FROM static_policies
         WHERE tenant_id = '';

        -- No enabled change here: the static loader's
        -- (tenant_id = $1 OR tenant_id = 'global') predicate excludes both ''
        -- and NULL for every caller, so this normalization does not change
        -- which policies are enforced.
        UPDATE static_policies SET tenant_id = NULL WHERE tenant_id = '';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        IF rows_updated > 0 THEN
            RAISE WARNING 'Migration 155: normalized % static_policies row(s) from tenant_id='''' to NULL (no enforcement change — both values fail the loader tenant predicate). Affected policy_id(s): %',
                rows_updated, affected_ids;
        END IF;
    END IF;
END
$$;

-- Part 2: constrain the shape out of existence.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'tenant_id')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'dynamic_policies_tenant_id_not_empty') THEN
        ALTER TABLE dynamic_policies
            ADD CONSTRAINT dynamic_policies_tenant_id_not_empty
            CHECK (tenant_id IS NULL OR tenant_id <> '');
        RAISE NOTICE 'Migration 155: added dynamic_policies_tenant_id_not_empty';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'static_policies_tenant_id_not_empty') THEN
        ALTER TABLE static_policies
            ADD CONSTRAINT static_policies_tenant_id_not_empty
            CHECK (tenant_id IS NULL OR tenant_id <> '');
        RAISE NOTICE 'Migration 155: added static_policies_tenant_id_not_empty';
    END IF;
END
$$;

-- Self-test: the constraints must exist and no empty-string tenant may remain.
DO $$
DECLARE
    remaining INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies' AND column_name = 'tenant_id') THEN
        SELECT COUNT(*) INTO remaining FROM dynamic_policies WHERE tenant_id = '';
        IF remaining > 0 THEN
            RAISE EXCEPTION 'Migration 155 failed: % dynamic_policies rows still have tenant_id=''''', remaining;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'dynamic_policies_tenant_id_not_empty') THEN
            RAISE EXCEPTION 'Migration 155 failed: dynamic_policies_tenant_id_not_empty missing';
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'static_policies' AND column_name = 'tenant_id') THEN
        SELECT COUNT(*) INTO remaining FROM static_policies WHERE tenant_id = '';
        IF remaining > 0 THEN
            RAISE EXCEPTION 'Migration 155 failed: % static_policies rows still have tenant_id=''''', remaining;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'static_policies_tenant_id_not_empty') THEN
            RAISE EXCEPTION 'Migration 155 failed: static_policies_tenant_id_not_empty missing';
        END IF;
    END IF;
END
$$;

COMMIT;
