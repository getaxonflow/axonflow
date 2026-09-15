-- Migration 185 (down): restore the patterns migrations/core/010 seeded for
-- sql_injection_or, sql_injection_union, drop_table_prevention and
-- truncate_prevention, on every row that carries the whole-word form 185 wrote.

UPDATE static_policies
   SET pattern = '(\bor\b|\band\b).*[''"]?\s*[=<>].*[''"]?\s*(or|and)\s*[''"]?\s*[=<>]',
       updated_at = NOW()
 WHERE pattern = '(\bor\b|\band\b).*[''"]?\s*[=<>].*[''"]?\s*\b(or|and)\b\s*[''"]?\s*[=<>]';

UPDATE static_policies
   SET pattern = 'union\s+select',
       updated_at = NOW()
 WHERE pattern = '\bunion\s+select\b';

UPDATE static_policies
   SET pattern = 'drop\s+table',
       updated_at = NOW()
 WHERE pattern = '\bdrop\s+table\b';

UPDATE static_policies
   SET pattern = 'truncate\s+table',
       updated_at = NOW()
 WHERE pattern = '\btruncate\s+table\b';
