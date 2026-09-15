-- Migration 179: delete sensitive_data_control, only where it is still the inert 010 seed
-- Date: 2026-09-11
-- Issue: #3323 (per-row decisions recorded under #3884)
--
-- 010_policy_tables.sql seeded dynamic_policies.sensitive_data_control with the
-- condition {"field":"query","operator":"contains","value":"salary|ssn|medical_record"}.
-- `contains` is a substring match, so it looks for that literal pipe-joined
-- string: it matches only an input containing "salary|ssn|medical_record"
-- verbatim, which no real query does. 031_seed_system_policies.sql seeded the
-- corrected row, sys_dyn_sensitive_data, with contains_any over the same three
-- terms and the same redact action.
--
-- The seed IS loaded. RefreshDynamicPolicies selects
-- COALESCE(category, '') and COALESCE(description, ''), so its NULL category
-- does not keep it out of the policy cache, and it is listed by
-- GET /api/v1/policies/dynamic, GET /api/v1/policies/{id} and the policy lists.
-- (This header once said the refresh's scan drops the row, as the v11 corpus
-- build's `legacy_scan_drop` reason for it still does; the loader does not do
-- that. The model behind that reason is #4078.)
--
-- Deleting the pristine seed changes no decision. Any input its condition
-- matches contains "salary", so sys_dyn_sensitive_data's contains_any matches
-- the same input with the same redact action.
-- runtime-e2e/3490_org_keyed_policy_selection measures that on a running
-- stack. What the delete removes is a row every customer's policy list shows
-- as an ENABLED redaction of salary, SSN and medical-record fields that, in
-- practice, never redacts anything.
--
-- ONLY THE PRISTINE SEED IS DELETED. A row that differs from its 010 seed in any
-- compared column is left exactly as it is, with a NOTICE: a customer who
-- categorised the row made it one the dynamic-policy routes serve, and one who
-- corrected its condition made it enforce. The compared columns, and where each comes from:
--   010  name, description, policy_type, risk_threshold, conditions, actions,
--        priority, tenant_id, enabled, metadata
--   022  version, created_by, updated_by
--   030  category, tags, deleted_at
--   070  risk_level (default 'medium'), allow_override (default TRUE)
--   159  segment_id
-- NOT compared: tier, org_id and client_id, which migrations 031, 090 and 153
-- rewrote on every global row, so a difference there is not an edit; id,
-- created_at and updated_at, which no edit signal lives in; and
-- organization_id, which 166 dropped. The import-overwrite path
-- (PolicyRepository.updatePolicyTx) bumps version and sets updated_by without
-- writing policy_versions, which is why both are compared rather than relying on
-- the history check below.
--
-- policy_versions.policy_id has ON DELETE CASCADE (022). The predicate requires
-- the row to have NO version history, so the cascade deletes nothing by
-- construction: a row with history is one somebody edited, and it is kept.
--
-- The superseder must be present, enabled, not soft-deleted, global, not
-- segment-scoped, and still carry 031's condition AND its redact action, or
-- nothing is deleted: a database holding 010's row and not a working 031 row
-- keeps what it has (#3323's guard requirement). The action is compared because
-- "no decision changes" rests on it: were the superseder edited to log instead
-- of redacting, the seed would be the only redaction left for its input.
--
-- Neither dynamic_policies nor policy_versions has FORCE ROW LEVEL SECURITY
-- (see migration 173's REVISIT note), so the migration role sees every row.
--
-- The static half of #3323 is deliberately NOT done here. Its five rows enforce
-- more than their superseders, and the supersession ledger decides keep_both
-- for each (platform/decision/registry/detectors_census_superseded.tsv).

BEGIN;

DO $$
DECLARE
    deleted_count INTEGER;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                   WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        RAISE NOTICE 'Migration 179: dynamic_policies missing - skipping';
        RETURN;
    END IF;

    DELETE FROM dynamic_policies dp
     WHERE dp.policy_id       = 'sensitive_data_control'
       AND dp.tenant_id       = 'global'
       AND dp.name            = 'Control Sensitive Data Access'
       AND dp.description     = 'Redact sensitive data fields in responses'
       AND dp.policy_type     = 'context_aware'
       AND dp.risk_threshold  = 0.50
       AND dp.conditions      = '[{"field": "query", "operator": "contains", "value": "salary|ssn|medical_record"}]'::jsonb
       AND dp.actions         = '[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]'::jsonb
       AND dp.priority        = 900
       AND dp.enabled         IS TRUE
       AND dp.category        IS NULL
       AND COALESCE(dp.version, 1) = 1
       AND dp.created_by      IS NULL
       AND dp.updated_by      IS NULL
       AND dp.deleted_at      IS NULL
       AND COALESCE(dp.metadata, '{}'::jsonb) = '{}'::jsonb
       AND COALESCE(dp.tags, '[]'::jsonb)     = '[]'::jsonb
       AND dp.segment_id      IS NULL
       AND dp.risk_level      = 'medium'
       AND dp.allow_override  IS TRUE
       AND NOT EXISTS (SELECT 1 FROM policy_versions pv WHERE pv.policy_id = dp.policy_id)
       AND EXISTS (SELECT 1 FROM dynamic_policies s
                    WHERE s.policy_id  = 'sys_dyn_sensitive_data'
                      AND s.enabled    IS TRUE
                      AND s.deleted_at IS NULL
                      AND s.tenant_id  = 'global'
                      AND s.segment_id IS NULL
                      AND s.conditions = '[{"field": "query", "operator": "contains_any", "value": ["salary", "ssn", "medical_record"]}]'::jsonb
                      AND s.actions    = '[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]'::jsonb);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    IF deleted_count > 0 THEN
        RAISE NOTICE 'Migration 179: deleted the pristine 010 seed sensitive_data_control (it matched only the literal string salary|ssn|medical_record; sys_dyn_sensitive_data redacts the same fields)';
    ELSIF EXISTS (SELECT 1 FROM dynamic_policies WHERE policy_id = 'sensitive_data_control') THEN
        RAISE NOTICE 'Migration 179: sensitive_data_control differs from its 010 seed, has version history, or sys_dyn_sensitive_data is not the working 031 row (condition, redact action, global, unsegmented) - left in place';
    ELSE
        RAISE NOTICE 'Migration 179: sensitive_data_control is absent - nothing to do';
    END IF;
END $$;

COMMIT;
