-- Migration 135: Syntactic-context hardening for false-positive-prone detectors
-- Date: 2026-07-03
-- Purpose: Design-partner debug report 2026-07-03 (epic #2800, WS-FP2 #2802):
--          documentation-only Jira edits were blocked by keyword/regex detectors
--          that matched plain English / Markdown, not executable input. This
--          hardens the WHOLE loose-verb security-sqli class (a bare verb in prose
--          is not a statement) plus the two dangerous-command detectors:
--            * sys_sqli_admin_bypass  — a Markdown table divider (`---` / `|---|---|`)
--              satisfied the SQL `--` comment requirement, and `[^'"]*` operands
--              spanned newlines across arbitrary prose.
--            * sys_sqli_revoke  — `\bREVOKE\s+` matched plain English ("will
--              revoke immediately after the single edit call").
--            * sys_sqli_grant   — `\bGRANT\s+` matched English ("grant viewer OR
--              editor access", the partner's own admin-console prose).
--            * sys_sqli_drop_table / _drop_database / _truncate / _alter_table /
--              _create_user — the bare two-word verb phrase (`\bDROP\s+TABLE\b`,
--              `\bCREATE\s+USER\b`, …) matched prose that merely NAMES the command
--              ("the drop table statement removes rows", "create user accounts").
--            * sys_sqli_delete_no_where — already specific; only TP-broadened
--              (schema-qualified/quoted identifiers, comment terminators).
--            * sys_dangerous_eval_exec — `eval\s*\(` matched inside hyphenated
--              identifiers followed by a parenthetical ("acme-eval (staging)")
--              because it had no left boundary and allowed whitespace before `(`.
--            * sys_dangerous_agent_config — a bare filename mention (`.env` in prose)
--              matched with no operational (write/exec) context.
--
--          SQL-grammar approach (mirrors sys_sqli_revoke): the DDL/DCL verbs now
--          require an object identifier + a statement terminator (`;`/`,`/`--`/`#`/
--          end-of-line/CASCADE/RESTRICT), or (GRANT/REVOKE) the full
--          `<privileges> ON ... TO|FROM <grantee>` shape; ALTER TABLE requires a
--          following action clause (ADD/DROP/RENAME/…). Comment terminators keep
--          stacked-query payloads (`DROP TABLE users--`) detected.
--
--          Each replacement pattern is NARROWER than the one it replaces —
--          every string the new pattern matches was already matched by the old
--          pattern — with ONE deliberate exception: sys_sqli_admin_bypass now
--          also catches the paren-grouped tautology (`') OR ('1'='1' --`), which
--          the old operand classes could not span. So this migration removes
--          false positives and adds exactly that one SQL-shaped form. True-
--          positive coverage is proven by the paired real-PG corpus test
--          (platform/agent/migration_135_detector_fp_test.go).
--
--          Documented narrowings (accepted, see #2802):
--            * admin_bypass: requires a quote/paren breakout (or a bare digit
--              tautology `OR 1=1`) and the `--` comment on the same line. An
--              UNQUOTED column self-comparison (`1 OR name=name --`) is not
--              caught — catching it would re-admit the partner's prose FP
--              (`... OR settings = same --- see docs`); the quote/paren/digit
--              forms cover the common cases and WS-FP1 capability scoping is the
--              class fix.
--            * revoke: requires SQL grammar — a privilege keyword plus ON ... FROM
--              with an SQL-shaped grantee (quoted/backtick, `user@host`, or a
--              bareword terminated by `;`/`,`/`@`/end-of-line, optionally
--              GROUP/ROLE/USER-qualified), or the MySQL `..., GRANT OPTION FROM`
--              form. Newlines are tolerated between REVOKE/ON/FROM (an attacker
--              controls formatting). Accepted narrowing: a bare role-membership
--              `REVOKE role FROM member` / `GRANT role TO member` with no privilege
--              keyword and no ON is NOT caught — it is indistinguishable from
--              English "grant/revoke X to/from Y" and catching it re-admits the
--              partner's documentation FP; WS-FP1 capability scoping is the class
--              fix. GRANT is the mirror of REVOKE (privilege + ON ... TO grantee).
--            * create_user: requires an object plus a real terminator (`;`/`,`/
--              `--`/`#`/`@`) or an attribute clause (IDENTIFIED / [WITH] SUPERUSER
--              / PASSWORD / LOGIN / CREATEDB / …). Accepted narrowing: an
--              attribute-less bare `CREATE USER x` is NOT caught — it is
--              indistinguishable from a doc heading ("Create User Roles"); every
--              privilege-bearing / escalation form carries an attribute keyword
--              and IS caught.
--            * eval_exec: `eval(`/`exec(` must be call syntax (a `(` after
--              optional whitespace) AND not be preceded by an identifier
--              character or hyphen, so `acme-eval(` / `retrieval(` are
--              identifiers, not calls, while `eval(`, `eval (`, and
--              `window.eval(` still match.
--            * agent_config: the protected filename must be either the operand of
--              a write/exec command (rm/mv/cp/tee/touch/chmod/chown/truncate/
--              unlink/shred/ln/install/sed, shell redirection incl. `>|` clobber,
--              `dd of=`, `open(`, curl/wget `-o`) OR a bare path at the START of
--              the statement (\A) — the Claude Code Write/Edit `file_path`, which
--              the plugin sends as the first line (`.env` or `config/.env`).
--              NOT a filename mentioned mid-sentence in prose, and NOT a bare
--              `.env` line elsewhere in the body (so editing a `.gitignore`/doc to
--              add a `.env` line is not blocked). Accepted residuals: a bareword
--              middle argument (`install secret .env`) is not caught (avoiding the
--              `touch base ... .env` idiom FP); a Write whose file_path is itself
--              `.env.example`/`.env.sample` is still matched (same as the old
--              pattern — RE2 has no negative lookahead to exclude template
--              suffixes). `sys_dangerous_credential_access` continues to govern
--              the read path (`cat ... .env`).
--
--          Patterns compile under Go RE2 (no lookarounds, linear-time — no
--          catastrophic backtracking is possible). The Go-side duplicates in
--          platform/agent/sqli/patterns.go (admin_bypass, revoke_privileges,
--          grant_privileges, drop_table, drop_database, truncate_table,
--          alter_table, create_user, delete_without_where) are updated in
--          lockstep in the same change.
-- Related: #2800, #2802. Precedents: migrations 063, 074, 124 (pattern-row UPDATE
--          via a NEW migration; shipped migrations are immutable).
-- IDEMPOTENT: each UPDATE is guarded on the ORIGINAL seeded pattern, so a
-- re-run (or a row a tenant has since customized — the two migration-059 rows
-- are tenant-tier and customer-editable) matches nothing and is left alone.

-- The hardened patterns are longer than the legacy varchar(500) cap (migration
-- 010), so widen static_policies.pattern to text first. Backward-compatible
-- (text accepts everything varchar(500) did; the loader scans the column into a
-- Go string regardless of type) and idempotent (skipped when already text). The
-- down migration restores the pattern VALUES but leaves the column as text —
-- shrinking could truncate a longer tenant-authored pattern, and nothing
-- depends on the varchar cap.
DO $$
BEGIN
    IF (SELECT data_type FROM information_schema.columns
        WHERE table_name = 'static_policies' AND column_name = 'pattern') <> 'text' THEN
        ALTER TABLE static_policies ALTER COLUMN pattern TYPE text;
    END IF;
END $$;

UPDATE static_policies
SET pattern    = '(?i)(?:[''"][\s)]*OR\s+\(?[''"]?[^''"\r\n]{0,64}?[''"]?\s*=\s*\(?[''"]?[^''"\r\n]{0,64}?[''"]?[ \t]*--|\bOR\s+\d{1,10}\s*=\s*\d{1,10}[ \t]*--)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_admin_bypass'
  AND tenant_id = 'global'
  AND pattern = '(?i)[''"]?\s*OR\s+[''"]?[^''"]*[''"]?\s*=\s*[''"]?[^''"]*[''"]?\s*--';

UPDATE static_policies
SET pattern    = '(?im)\bREVOKE\s+(?:GRANT\s+OPTION\s+FOR\s+)?(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|MAINTAIN|EXECUTE|USAGE|CREATE|CONNECT|TEMPORARY|TEMP|TRIGGER|REFERENCES|INDEX|ALTER|DROP)\b(?:[^;]{0,200}?\bON\b[^;]{0,200}?\bFROM\s+(?:GROUP\s+|ROLE\s+|USER\s+)?(?:[\x60''"]|\w+\s*(?:;|,|@|$|--|\#|\bCASCADE\b|\bRESTRICT\b))|\s*,\s*GRANT\s+OPTION\s+FROM\b)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_revoke'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bREVOKE\s+';

UPDATE static_policies
SET pattern    = '(?im)\bGRANT\s+(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|MAINTAIN|EXECUTE|USAGE|CREATE|CONNECT|TEMPORARY|TEMP|TRIGGER|REFERENCES|INDEX|ALTER|DROP)\b[^;]{0,200}?\bON\b[^;]{0,200}?\bTO\s+(?:GROUP\s+|ROLE\s+|USER\s+)?(?:[\x60''"]|\w+\s*(?:;|,|@|$|--|\#|\bWITH\b|\bCASCADE\b))',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_grant'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bGRANT\s+';

UPDATE static_policies
SET pattern    = '(?im)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|\z|\bCASCADE\b|\bRESTRICT\b)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_drop_table'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bDROP\s+TABLE\b';

UPDATE static_policies
SET pattern    = '(?im)\bDROP\s+DATABASE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|\z)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_drop_database'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bDROP\s+DATABASE\b';

UPDATE static_policies
SET pattern    = '(?im)\bTRUNCATE\s+TABLE\s+(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|\z|\bCASCADE\b|\bRESTART\b|\bCONTINUE\b)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_truncate'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bTRUNCATE\s+TABLE\b';

UPDATE static_policies
SET pattern    = '(?im)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s+(?:ADD|DROP|ALTER|RENAME|MODIFY|CHANGE|ENABLE|DISABLE|OWNER|SET)\b',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_alter_table'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bALTER\s+TABLE\b';

UPDATE static_policies
SET pattern    = '(?im)\bCREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"''\w.$\[\]]+\s*(?:;|,|--|\#|@|(?:\bWITH\s+)?\b(?:IDENTIFIED|SUPERUSER|CREATEDB|CREATEROLE|LOGIN|NOLOGIN|PASSWORD|VALID)\b)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_create_user'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bCREATE\s+USER\b';

UPDATE static_policies
SET pattern    = '(?im)\bDELETE\s+FROM\s+[\x60"''\w.$\[\]]+\s*(?:;|--|\#|\z)',
    updated_at = NOW()
WHERE policy_id = 'sys_sqli_delete_no_where'
  AND tenant_id = 'global'
  AND pattern = '(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)';

UPDATE static_policies
SET pattern    = '((?:^|[^A-Za-z0-9_$-])(?:eval|exec)\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()',
    updated_at = NOW()
WHERE policy_id = 'sys_dangerous_eval_exec'
  AND tenant_id = 'global'
  AND pattern = '(eval\s*\(|exec\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()';

UPDATE static_policies
SET pattern    = '(?m)(?:(?:\b(?:rm|del|mv|cp|tee|touch|chmod|chown|truncate|unlink|shred|ln|install|sed)\s+(?:(?:-{1,2}[\w=/,.:@-]+|\d{1,4}|[\w-]*[/.~][\w~./\\${}-]*|''[^''\r\n]{0,80}''|"[^"\r\n]{0,80}")\s+){0,12}|[^\r\n>][ \t]*>>?\|?[ \t]*|\bof=|\bopen\s*\(\s*[''"]?|\b(?:curl|wget)\b[^\r\n;|&]{0,120}\s(?:-o|-O|--output|--output-document)\s+)[''"]?[\w~./\\${}-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json)\b|\A[ \t]*[''"]?[\w~./\\${}-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json)[''"]?[ \t]*$|"file_path"\s*:\s*"[\w~./\\${}-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json))',
    updated_at = NOW()
WHERE policy_id = 'sys_dangerous_agent_config'
  AND tenant_id = 'global'
  AND pattern = '(\.env\b|\.env\.local|\.env\.production|credentials\.json|service-account\.json)';

-- Fail-loud verification: NO detector row may still carry its pre-135 seed
-- pattern. A leftover old-seed row means the UPDATE above should have fired but
-- did not (partial apply / migration-order regression) — that ships a silently
-- un-hardened detector, so we abort. Keyed on the OLD seed (not the new
-- pattern) so it is: fail-loud on a true partial apply; safe to re-run (after
-- success no row equals the old seed); and tolerant of a legitimately
-- customized global row (neither old nor new -> not counted).
DO $$
DECLARE
    stale_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO stale_count
    FROM static_policies
    WHERE tenant_id = 'global'
      AND (
        (policy_id = 'sys_sqli_admin_bypass' AND pattern = '(?i)[''"]?\s*OR\s+[''"]?[^''"]*[''"]?\s*=\s*[''"]?[^''"]*[''"]?\s*--')
     OR (policy_id = 'sys_sqli_revoke' AND pattern = '(?i)\bREVOKE\s+')
     OR (policy_id = 'sys_sqli_grant' AND pattern = '(?i)\bGRANT\s+')
     OR (policy_id = 'sys_sqli_drop_table' AND pattern = '(?i)\bDROP\s+TABLE\b')
     OR (policy_id = 'sys_sqli_drop_database' AND pattern = '(?i)\bDROP\s+DATABASE\b')
     OR (policy_id = 'sys_sqli_truncate' AND pattern = '(?i)\bTRUNCATE\s+TABLE\b')
     OR (policy_id = 'sys_sqli_alter_table' AND pattern = '(?i)\bALTER\s+TABLE\b')
     OR (policy_id = 'sys_sqli_create_user' AND pattern = '(?i)\bCREATE\s+USER\b')
     OR (policy_id = 'sys_sqli_delete_no_where' AND pattern = '(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)')
     OR (policy_id = 'sys_dangerous_eval_exec' AND pattern = '(eval\s*\(|exec\s*\(|__import__|subprocess\.call|os\.system\s*\(|os\.popen\s*\()')
     OR (policy_id = 'sys_dangerous_agent_config' AND pattern = '(\.env\b|\.env\.local|\.env\.production|credentials\.json|service-account\.json)')
      );

    IF stale_count > 0 THEN
        RAISE EXCEPTION 'Migration 135: % detector row(s) still carry a pre-135 seed pattern — partial apply or migration-order regression; aborting so an un-hardened detector is never shipped', stale_count;
    END IF;
    RAISE NOTICE 'Migration 135 verified: no detector row still carries a pre-135 seed pattern';
END $$;
