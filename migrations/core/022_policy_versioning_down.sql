-- Rollback migration 022: Policy Versioning

DROP POLICY IF EXISTS policy_versions_tenant_isolation ON policy_versions;
DROP TABLE IF EXISTS policy_versions;

ALTER TABLE dynamic_policies
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS updated_by;

DROP INDEX IF EXISTS idx_dynamic_policies_version;
