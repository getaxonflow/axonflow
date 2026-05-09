-- 084_record_policy_version_down.sql
-- Rollback for the policy_version JSONB-key addition. There is no DDL to
-- reverse — α1 only added optional JSONB keys produced by the application
-- layer. To "rollback" a deployment, deploy the prior application image;
-- the new keys naturally stop being written.
--
-- Existing audit rows already written with policy_version are untouched
-- (forward-only data). They remain valid JSONB; readers that don't know
-- about the keys ignore them per ADR-043 §"Versioning".

SELECT 'migration 084 down is doc-only — no DDL. See file header.' AS note;
