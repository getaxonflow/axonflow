-- Migration 135 DOWN: restore the pre-hardening detector patterns
-- Reverts the four pattern rows to their original seeded regexes
-- (migrations 031 / 059 verbatim). Scoped by policy_id + the migration-135
-- pattern so a row a tenant has since customized is left untouched.
-- IDEMPOTENT: the WHERE matches nothing on re-run.

UPDATE static_policies
SET pattern    = '(?i)[''"]?\s*OR\s+[''"]?[^''"]*[''"]?\s*=\s*[''"]?[^''"]*[''"]?\s*--',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_admin_bypass'
  AND tenant_id = 'global'
  AND pattern = '(?i)(?:[''"][\s)]*OR\s+\(?[''"]?[^''"\r\n]{0,64}?[''"]?\s*=\s*\(?[''"]?[^''"\r\n]{0,64}?[''"]?[ \t]*--|\bOR\s+\d{1,10}\s*=\s*\d{1,10}[ \t]*--)';

UPDATE static_policies
SET pattern    = '(?i)\bREVOKE\s+',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_revoke'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bREVOKE\s+(?:GRANT\s+OPTION\s+FOR\s+)?(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|MAINTAIN|EXECUTE|USAGE|CREATE|CONNECT|TEMPORARY|TEMP|TRIGGER|REFERENCES|INDEX|ALTER|DROP)\b(?:[^;]{0,200}?\bON\b[^;]{0,200}?\bFROM\s+(?:GROUP\s+|ROLE\s+|USER\s+)?(?:[\x60''"]|\w+\s*(?:;|,|@|$|--|\#|\bCASCADE\b|\bRESTRICT\b))|\s*,\s*GRANT\s+OPTION\s+FROM\b)';

UPDATE static_policies
SET pattern    = '(?i)\bGRANT\s+',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_grant'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bGRANT\s+(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|MAINTAIN|EXECUTE|USAGE|CREATE|CONNECT|TEMPORARY|TEMP|TRIGGER|REFERENCES|INDEX|ALTER|DROP)\b[^;]{0,200}?\bON\b[^;]{0,200}?\bTO\s+(?:GROUP\s+|ROLE\s+|USER\s+)?(?:[\x60''"]|\w+\s*(?:;|,|@|$|--|\#|\bWITH\b|\bCASCADE\b))';

UPDATE static_policies
SET pattern    = '(?i)\bDROP\s+TABLE\b',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_drop_table'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|\z|\bCASCADE\b|\bRESTRICT\b)';

UPDATE static_policies
SET pattern    = '(?i)\bDROP\s+DATABASE\b',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_drop_database'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bDROP\s+DATABASE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|\z)';

UPDATE static_policies
SET pattern    = '(?i)\bTRUNCATE\s+TABLE\b',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_truncate'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bTRUNCATE\s+TABLE\s+(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|\z|\bCASCADE\b|\bRESTART\b|\bCONTINUE\b)';

UPDATE static_policies
SET pattern    = '(?i)\bALTER\s+TABLE\b',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_alter_table'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s+(?:ADD|DROP|ALTER|RENAME|MODIFY|CHANGE|ENABLE|DISABLE|OWNER|SET)\b';

UPDATE static_policies
SET pattern    = '(?i)\bCREATE\s+USER\b',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_create_user'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bCREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|@|(?:\bWITH\s+)?\b(?:IDENTIFIED|SUPERUSER|CREATEDB|CREATEROLE|LOGIN|NOLOGIN|PASSWORD|VALID)\b)';

UPDATE static_policies
SET pattern    = '(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_delete_no_where'
  AND tenant_id = 'global'
  AND pattern = '(?im)\bDELETE\s+FROM\s+[\x60"''\w.$\[\]]+\s*(?:;|--|\#|\z)';

UPDATE static_policies
SET pattern    = '(eval\s*\(|exec\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()',
    updated_at = NOW()
WHERE policy_id = 'sys_dangerous_eval_exec'
  AND tenant_id = 'global'
  AND pattern = '((?:^|[^A-Za-z0-9_$-])(?:eval|exec)\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()';

UPDATE static_policies
SET pattern    = '(\.env\b|\.env\.local|\.env\.production|credentials\.json|service-account\.json)',
    updated_at = NOW()
WHERE policy_id = 'sys_dangerous_agent_config'
  AND tenant_id = 'global'
  AND pattern = '(?m)(?:(?:\b(?:rm|del|mv|cp|tee|touch|chmod|chown|truncate|unlink|shred|ln|install|sed)\s+(?:(?:-{1,2}[\w=/,.:@-]+|\d{1,4}|[\w-]*[/.~][\w~./\\${}-]*|''[^''\r\n]{0,80}''|"[^"\r\n]{0,80}")\s+){0,12}|[^\r\n>][ \t]*>>?\|?[ \t]*|\bof=|\bopen\s*\(\s*[''"]?|\b(?:curl|wget)\b[^\r\n;|&]{0,120}\s(?:-o|-O|--output|--output-document)\s+)[''"]?[\w~./\\${}-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json)\b|\A[ \t]*[''"]?[\w~./\\${}-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json)[''"]?[ \t]*$|"file_path"\s*:\s*"[\w~./\\${}-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json))';
