// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package sqli

import (
	"testing"
)

// patternByName fetches a compiled pattern from the default set by name.
func patternByName(t *testing.T, name string) *Pattern {
	t.Helper()
	for _, p := range NewPatternSet().Patterns() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("pattern %q not found in default pattern set", name)
	return nil
}

// TestFPHardening_AdminBypassAndRevoke locks in the #2802 hardening of the two
// scanner patterns that mirror migration core/135 (sys_sqli_admin_bypass and
// sys_sqli_revoke): the design partner's verbatim documentation-only triggers
// must NOT match, while the real attack corpus must STILL match. The regexes
// are tested directly (not through Scanner.Scan) because the scanner reports
// only the first matching pattern, which would let an unrelated pattern mask a
// regression here. Red-on-revert: restoring either pre-135 regex fails the FP
// half of this test.
func TestFPHardening_AdminBypassAndRevoke(t *testing.T) {
	adminBypass := patternByName(t, "admin_bypass")
	revoke := patternByName(t, "revoke_privileges")

	falsePositives := []struct {
		name    string
		pattern *Pattern
		input   string
	}{
		// admin_bypass FPs: Markdown table dividers satisfying the `--` comment
		// marker plus prose OR-equals (partner finding 1: "admin console", table
		// dividers, no SQL, no quotes).
		{"markdown table + prose or-equals", adminBypass, "## Rollout Plan\n\n| Component | Status |\n|---|---|\n| admin console | pending |\n\nGrant viewer OR editor = acceptable for this phase.\n\n---\n\nNext steps below."},
		{"prose or-equals + divider next line", adminBypass, "Set the flag to A OR B = C in the admin console\n---\nfooter"},
		{"same-line triple dash", adminBypass, "| Option | Meaning |\n|---|---|\nUse admin console OR settings page = same effect --- see docs"},
		// revoke FPs: plain English uses of the verb (partner finding 5, verbatim).
		{"revoke immediately", revoke, "I will revoke immediately after the single edit call."},
		{"revoke access from", revoke, "We should revoke access from all contractors next week."},
		{"revoke the token", revoke, "Please revoke the API token once the migration completes."},
		{"revoke all on friday from", revoke, "The admin can revoke all permissions on Friday from the dashboard settings page going forward."},
	}
	for _, tt := range falsePositives {
		t.Run("fp/"+tt.name, func(t *testing.T) {
			if tt.pattern.Regex.MatchString(tt.input) {
				t.Errorf("documentation text matched %s (false positive): %q", tt.pattern.Name, tt.input)
			}
		})
	}

	truePositives := []struct {
		name    string
		pattern *Pattern
		input   string
	}{
		{"classic or 1=1 comment", adminBypass, `' OR 1=1 --`},
		{"quoted tautology", adminBypass, `admin' OR '1'='1' --`},
		{"no-space comment", adminBypass, `admin' OR 1=1--`},
		{"bare digit tautology", adminBypass, `1 OR 1=1 --`},
		{"paren-grouped tautology", adminBypass, `') OR ('1'='1' --`},
		{"empty-string tautology", adminBypass, `" OR ""="" --`},
		{"json-wrapped payload", adminBypass, `{"query":"admin' OR 1=1 --"}`},
		{"revoke all on from", revoke, `REVOKE ALL ON db FROM user;`},
		{"mysql revoke wildcard", revoke, `REVOKE ALL PRIVILEGES ON *.* FROM 'attacker'@'%';`},
		{"lowercase privilege list", revoke, `revoke select, insert ON app.orders FROM analyst;`},
		{"mysql grant-option form", revoke, `REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'u'@'h';`},
		{"grant option for", revoke, `REVOKE GRANT OPTION FOR SELECT ON t FROM PUBLIC;`},
		{"function execute", revoke, `REVOKE EXECUTE ON FUNCTION pg_read_file(text) FROM app_role;`},
		{"no trailing semicolon", revoke, `REVOKE SELECT ON orders FROM analyst`},
		{"no-semicolon bareword grantee", revoke, `REVOKE ALL PRIVILEGES ON *.* FROM attacker`},
		{"multiline formatting", revoke, "REVOKE ALL\n ON db\n FROM user;"},
		{"mysql GROUP grantee", revoke, `REVOKE ALL ON db FROM GROUP dev;`},
		{"grantee at end-of-line", revoke, "REVOKE SELECT ON t FROM analyst\nSELECT 1"},
	}
	for _, tt := range truePositives {
		t.Run("tp/"+tt.name, func(t *testing.T) {
			if !tt.pattern.Regex.MatchString(tt.input) {
				t.Errorf("attack payload NOT matched by %s (true-positive coverage weakened): %q", tt.pattern.Name, tt.input)
			}
		})
	}
}

// TestStringTermComment_CommentOutAuthBypass locks in the #2811 detector that
// mirrors migration core/139 (sys_sqli_string_term_comment): the OWASP
// comment-out auth bypass (a string-literal terminator directly followed by a
// SQL line comment ending the line) must match, while the documentation-prose
// FP class the #2802 hardening protects (prose dashes, doc examples quoting
// the vulnerable clause, Markdown dividers, apostrophe-hash idioms) must NOT.
// The precondition-absent direction is covered by fp cases that share the
// payload shape but continue with text after the comment.
func TestStringTermComment_CommentOutAuthBypass(t *testing.T) {
	p := patternByName(t, "string_term_comment")

	truePositives := []struct {
		name  string
		input string
	}{
		{"classic spaced", `admin' --`},
		{"no-space", `x'--`},
		{"mysql hash", `x'#`},
		{"mysql safe variant", `admin'-- -`},
		{"multi dash no space", `admin'---`},
		{"double quote", `admin" --`},
		{"paren breakout", `admin') --`},
		{"trailing whitespace", "admin' -- "},
		{"embedded line of a larger body", "first line\nadmin' --\nlast line"},
		{"crlf line ending", "admin' --\r\nnext"},
	}
	for _, tt := range truePositives {
		t.Run("tp/"+tt.name, func(t *testing.T) {
			if !p.Regex.MatchString(tt.input) {
				t.Errorf("comment-out payload NOT matched by %s: %q", p.Name, tt.input)
			}
		})
	}

	falsePositives := []struct {
		name  string
		input string
	}{
		{"prose dash continuation", `she said 'stop' -- then left the room`},
		{"doc example quoting the vulnerable clause", `The query becomes WHERE user='admin'--' AND pass=... which bypasses auth.`},
		{"markdown table divider", "| Step | Owner |\n|---|---|\n| Enable | Platform |"},
		{"markdown horizontal rule", "Intro paragraph.\n\n---\n\nNext section."},
		{"apostrophe hash idiom", `it's #1 priority for the team`},
		{"possessive hashtag", `the employees' #standup channel`},
		{"legit sql comment with text", `SELECT * FROM t WHERE name = 'x' -- filter by name`},
		{"mysql hash comment with text", `SELECT 1 FROM t WHERE s = 'x' # trailing note`},
		{"quoted hex color", `set the badge color to '#ff0000' in settings`},
		{"bare double dash at line end no quote", "run the migration --\nthen verify"},
		// Balanced-quote token with a trailing EMPTY comment on an EXECUTION
		// connector (NOT text-document-scoped): the first quote closes its own
		// literal, so the breakout gate excludes it. These are the FP class the
		// naive end-of-line-only pattern denied under SQLI_ACTION=block.
		{"shell echo with trailing hash", `echo 'done'  #`},
		{"git commit with trailing hash", `git commit -m 'wip' #`},
		{"sql select with trailing empty dash comment", `SELECT count(*) FROM t WHERE region='EU' --`},
		{"python call with trailing hash", `print('hello')  #`},
		{"assignment call with trailing hash", `x = compute('a')  #`},
	}
	for _, tt := range falsePositives {
		t.Run("fp/"+tt.name, func(t *testing.T) {
			if p.Regex.MatchString(tt.input) {
				t.Errorf("benign text matched %s (false positive): %q", p.Name, tt.input)
			}
		})
	}

	// Documented residual: the fully-concatenated form (comment mid-line with
	// trailing SQL) is NOT caught — it is regex-indistinguishable from a benign
	// trailing SQL comment containing a quote. Locked in so a future widening
	// that tries to catch it is forced to confront the FP twin below.
	residualNonMatches := []struct {
		name  string
		input string
	}{
		{"concatenated full statement", `SELECT * FROM users WHERE user='admin' --' AND pass='x'`},
		{"value with internal quote", `O'Brien' --`},
	}
	for _, tt := range residualNonMatches {
		t.Run("residual/"+tt.name, func(t *testing.T) {
			if p.Regex.MatchString(tt.input) {
				t.Logf("NOTE: %s now matches %q — a widening; ensure the benign twin (region='EU' -- it's a note) still does not", p.Name, tt.input)
			}
		})
	}
}
