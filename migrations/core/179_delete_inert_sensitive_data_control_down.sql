-- Migration 179 DOWN: restore sensitive_data_control
-- Pairs with: 179_delete_inert_sensitive_data_control.sql
--
-- Re-seeds the row with the content 179 required it to have: every column 010
-- wrote, and client_id = 'global', which migration 090 backfilled from
-- tenant_id on every global row and no trigger fills on insert. Every other
-- compared column takes its column default, which is the value 179 required.
-- What is NOT restored is identity: id, created_at and updated_at are new,
-- because the row 179 deleted is gone. ON CONFLICT DO NOTHING mirrors 010's own
-- idempotent insert and leaves a row 179 kept untouched.
--
-- The down cannot tell a row 179 deleted from one a customer deleted before 179
-- ran, so it re-creates the seed in both cases; the NOTICE says which happened.

BEGIN;

DO $$
DECLARE
    restored INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        INSERT INTO dynamic_policies (policy_id, name, description, policy_type, risk_threshold, conditions, actions, priority, tenant_id, client_id) VALUES
        ('sensitive_data_control', 'Control Sensitive Data Access', 'Redact sensitive data fields in responses', 'context_aware', 0.5,
            '[{"field": "query", "operator": "contains", "value": "salary|ssn|medical_record"}]',
            '[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]',
            900, 'global', 'global')
        ON CONFLICT (policy_id) DO NOTHING;
        GET DIAGNOSTICS restored = ROW_COUNT;
        IF restored > 0 THEN
            RAISE NOTICE 'Migration 179 DOWN: restored sensitive_data_control';
        ELSE
            RAISE NOTICE 'Migration 179 DOWN: sensitive_data_control is present - left as it is';
        END IF;
    END IF;
END $$;

COMMIT;
