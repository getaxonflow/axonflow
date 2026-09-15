-- Migration 185: the organization template's SQL keyword rows match whole words only
-- Date: 2026-09-13
-- Purpose: Four patterns migrations/core/010 seeded for the organization
--          template lack a word boundary where a word must start or end. Once
--          #4131 bound them on /api/request (block) and compiled the
--          SQL-injection and destructive-command families case-insensitively,
--          each would refuse ordinary text, a refusal no v10 engine ever gave
--          (no v10 plane evaluated these rows):
--            sql_injection_or       the second (or|and) group matches the END of
--                                   a field name: "... AND color = 'red' AND
--                                   brand = 'acme'" matches through "brand =";
--            sql_injection_union    "the reunion selection committee met";
--            drop_table_prevention  "backdrop tablet stand";
--            truncate_prevention    "truncate tables to 10 rows".
--          Each gains \b where a word must start or end, and every injection and
--          destructive statement the rows caught still matches. Whole-word prose
--          ("Did the union select a new leader?") still matches: that is the
--          limit of a keyword pattern, recorded on #4231.
-- Related: #4131, #4231 (the keyword limit, and sql_injection_or's recall gap:
--          "1 OR 1=1" and "admin' AND 1=1 AND 'a'='a" are still missed), #3323
--          (its cleanup re-censuses these four rows against this migration, not
--          010), migrations/core/010.
--
-- WHICH ROWS: every static_policies row whose pattern IS a shipped literal, in
-- every organization. policy_id is unique (core/010), so an organization's copy
-- of a template row carries another id and only its pattern identifies it; an
-- organization's own row that typed the same literal gets the same fix. A
-- pattern anyone edited is left alone. A second run finds no row with an old
-- literal, so the migration is idempotent.
--
-- EDITION: COMMUNITY (mirrored). The organization template and /api/request
-- ship on every edition.

UPDATE static_policies
   SET pattern = '(\bor\b|\band\b).*[''"]?\s*[=<>].*[''"]?\s*\b(or|and)\b\s*[''"]?\s*[=<>]',
       updated_at = NOW()
 WHERE pattern = '(\bor\b|\band\b).*[''"]?\s*[=<>].*[''"]?\s*(or|and)\s*[''"]?\s*[=<>]';

UPDATE static_policies
   SET pattern = '\bunion\s+select\b',
       updated_at = NOW()
 WHERE pattern = 'union\s+select';

UPDATE static_policies
   SET pattern = '\bdrop\s+table\b',
       updated_at = NOW()
 WHERE pattern = 'drop\s+table';

UPDATE static_policies
   SET pattern = '\btruncate\s+table\b',
       updated_at = NOW()
 WHERE pattern = 'truncate\s+table';
