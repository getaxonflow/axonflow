-- Down for migration 139: remove the comment-out SQLi auth-bypass detector.
-- The row is system-tier (immutable, not customer-editable), so a plain
-- keyed DELETE is safe -- there is no tenant-customized variant to preserve
-- (contrast the migration-135 guard for the tenant-tier migration-059 rows).
-- IDEMPOTENT: the DELETE matches nothing on re-run.

DELETE FROM static_policies
WHERE policy_id = 'sys_sqli_string_term_comment'
  AND tier = 'system';
