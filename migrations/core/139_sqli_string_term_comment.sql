-- Migration 139: Comment-out SQL-injection auth-bypass detector
-- Date: 2026-07-03
-- Purpose: #2811 (epic #2800): the classic OWASP comment-out authentication
--          bypass -- appending a string-literal terminator plus a SQL line
--          comment to a value so the rest of the WHERE clause is commented
--          out (admin' --) -- passed clean through every governed input
--          plane. The tautology form (' OR '1'='1' -- , sys_sqli_admin_bypass)
--          and the stacked-query forms ARE caught; the bare comment-out form
--          was not: the existing comment detectors (sys_sqli_line_comment_dash
--          / _mysql, migration 031) require a SQL keyword AFTER the comment,
--          which this payload does not carry.
--
--          New detector sys_sqli_string_term_comment: a string-literal
--          terminator (single or double quote, optionally followed by closing
--          parens) directly followed by a SQL line comment (-- or #) that ends
--          the line, where that quote is the FIRST quote on the line. TWO gates
--          keep documentation and benign shell/SQL prose out:
--            1. First-quote breakout (^[^'"\r\n]*['"]): the value has no earlier
--               quote of its own, so the lone quote is a BREAKOUT that closes the
--               surrounding SQL string literal. A benign quoted token
--               (echo 'done' #, git commit -m 'wip', region='EU' --) opens and
--               CLOSES its own literal, so its first quote is followed by the
--               token's content, not the comment -> no match. This is the tell
--               that separates the auth-bypass (unbalanced trailing quote) from
--               an ordinary quoted argument with a trailing comment.
--            2. End-of-line anchor: the comment is the end of the line, because
--               in the bypass everything behind it is commented out. Prose dashes
--               that continue with text ("she said 'stop' -- then left"), a doc
--               example quoting the vulnerable clause
--               (WHERE user='admin'--' AND pass=...), and an apostrophe-hash
--               idiom ("it's #1 priority") all carry text after the comment
--               -> no match. Markdown table dividers / horizontal rules carry no
--               quote at all -> no match.
--          The genuine isolated payload matches: admin' -- , x'-- , x'# , the
--          MySQL-safe variant admin'-- - , and multi-dash admin'--- .
--
--          Accepted residuals (documented, mirror the 135 methodology):
--            * FULLY-CONCATENATED form -- the reconstructed statement
--              WHERE user='admin' --' AND pass='x' , where the comment sits
--              mid-line with trailing SQL -- is NOT caught. It is regex-
--              indistinguishable from a benign SQL statement carrying a trailing
--              line comment that happens to contain a quote (region='EU' -- it's
--              fine): both are <quote> ... -- ... <quote>. This detector covers
--              the ISOLATED comment-out value (the #2811 repro: the statement
--              field IS `admin' --`), which is what a PEP client sends as the
--              tool argument. The concatenated-in-full-SQL form is tracked as a
--              known gap (fptpcorpus tp-owasp-concat-comment) and is addressed by
--              capability scoping (#2801, ADR-059) + parameterized queries, not
--              by a standalone-token regex.
--            * A value whose own content contains an earlier quote
--              (O'Brien' --) has its first quote consumed by that content and is
--              NOT caught -- rare for an auth-bypass token.
--          Both residuals fail SAFE toward fewer FPs; the family default action
--          is warn (ADR-036, migrations 066/067/124) and capability scoping
--          removes text-document tools from the whole category.
--
--          The pattern compiles under Go RE2 ((?m) multi-line, no lookarounds,
--          linear time). Row shape mirrors the post-124 security-sqli family
--          state: base action warn, phase columns warn (the AXONFLOW_PROFILE
--          override drives enforcement), severity high, priority 90.
--          Capability scoping applies automatically: security-sqli is a
--          category-scoped execution class (platform/shared/policy/
--          capability.go), so no classification change is needed.
--
--          Go-side lockstep: platform/agent/sqli/patterns.go gains the
--          mirrored string_term_comment pattern in the same change.
-- Related: #2811, #2800, #2802. Precedents: migration 116 (row INSERT via a
--          NEW migration; shipped migrations are immutable), 135 (syntactic
--          FP gating), 124 (family action alignment).
-- IDEMPOTENT: INSERT ... ON CONFLICT (policy_id) DO NOTHING.

INSERT INTO static_policies (policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by, phase, action_request, action_response)
VALUES
  ('sys_sqli_string_term_comment', 'String-Terminator Comment Injection', 'security-sqli', 'system',
   '(?m)^[^''"\r\n]*[''"][ \t)]*(?:--|#)[ \t-]*\r?$',
   'high', 'Detects a breakout string-literal terminator (the first quote on the line) directly followed by a SQL line comment that ends the line (comment-out authentication bypass, OWASP)',
   'warn', 90, true, 'global', 'system', 'both', 'warn', 'warn')
ON CONFLICT (policy_id) DO NOTHING;

-- Fail-loud verification: the row must exist and stay aligned with the
-- security-sqli family posture (warn base + warn phase actions, ADR-036/124).
DO $$
DECLARE
    row_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO row_count
    FROM static_policies
    WHERE policy_id = 'sys_sqli_string_term_comment'
      AND tier = 'system'
      AND enabled = true;
    IF row_count <> 1 THEN
        RAISE EXCEPTION 'Migration 139: sys_sqli_string_term_comment row missing after INSERT';
    ELSE
        RAISE NOTICE 'Migration 139 verified: sys_sqli_string_term_comment seeded (security-sqli, warn)';
    END IF;
END $$;
