// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"reflect"
	"strings"
	"testing"
)

// TestReadOnlyPostureEnabled verifies the single env toggle parses the same
// truthy/falsey forms as every other MCP master switch and defaults OFF.
func TestReadOnlyPostureEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string
		set  bool
		want bool
	}{
		{"unset defaults off", "", false, false},
		{"empty defaults off", "", true, false},
		{"true", "true", true, true},
		{"TRUE uppercase", "TRUE", true, true},
		{"1", "1", true, true},
		{"yes", "yes", true, true},
		{"  true  whitespace", "  true  ", true, true},
		{"false", "false", true, false},
		{"0", "0", true, false},
		{"no", "no", true, false},
		{"garbage falls back off", "maybe", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(EnvMCPReadOnly, tc.env)
			}
			if got := readOnlyPostureEnabled(); got != tc.want {
				t.Errorf("readOnlyPostureEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyMCPCall is the authoritative spec for the read/write rule. Each
// case documents an edge the docs page promises (docs/governance/read-only-posture.md).
func TestClassifyMCPCall(t *testing.T) {
	tests := []struct {
		name          string
		connectorType string
		operation     string
		want          mcpAccessClass
	}{
		// --- Read-path tools are allowed (classified read) ---
		{"claude_code.Read", "claude_code.Read", "execute", mcpAccessRead},
		{"claude_code.Grep", "claude_code.Grep", "execute", mcpAccessRead},
		{"claude_code.Glob", "claude_code.Glob", "execute", mcpAccessRead},
		{"db.Query", "db.Query", "query", mcpAccessRead},
		{"get_user snake", "user_service.get_user", "execute", mcpAccessRead},
		{"list_items", "list_items", "execute", mcpAccessRead},
		{"search_flights", "travel.search_flights", "execute", mcpAccessRead},
		{"describe_table", "postgres.describe_table", "execute", mcpAccessRead},
		{"select prefix snake", "postgres.select_users", "execute", mcpAccessRead},
		{"camelCase getUserList", "svc.getUserList", "execute", mcpAccessRead},

		// --- Write-path tools are blocked (classified write) ---
		{"claude_code.Write", "claude_code.Write", "execute", mcpAccessWrite},
		{"claude_code.Edit", "claude_code.Edit", "execute", mcpAccessWrite},
		{"claude_code.Bash", "claude_code.Bash", "execute", mcpAccessWrite},
		{"db.Execute", "db.Execute", "execute", mcpAccessWrite},
		{"create_record", "svc.create_record", "execute", mcpAccessWrite},
		{"delete_row", "db.delete_row", "execute", mcpAccessWrite},
		{"update_config", "svc.update_config", "execute", mcpAccessWrite},
		{"camelCase deleteUser", "svc.deleteUser", "execute", mcpAccessWrite},
		{"PascalCase RunCommand", "shell.RunCommand", "execute", mcpAccessWrite},

		// --- Write wins over read when both verbs present (fail-safe) ---
		{"read_or_write -> write", "svc.read_or_write", "query", mcpAccessWrite},
		{"get_and_delete -> write", "svc.get_and_delete", "query", mcpAccessWrite},

		// --- Mutating verbs that MUST block even with operation=query (R3 round 1
		//     hardening: these were not caught by the first cut's verb list, so a
		//     caller asserting operation=query could have slipped a write through). ---
		{"upload + query -> write", "files.upload", "query", mcpAccessWrite},
		{"add_user + query -> write", "svc.add_user", "query", mcpAccessWrite},
		{"merge_rows + query -> write", "db.merge_rows", "query", mcpAccessWrite},
		{"transfer_funds + query -> write", "bank.transfer_funds", "query", mcpAccessWrite},
		{"grant_role + query -> write", "iam.grant_role", "query", mcpAccessWrite},
		{"revoke_token + query -> write", "iam.revoke_token", "query", mcpAccessWrite},
		{"reset_password + query -> write", "svc.reset_password", "query", mcpAccessWrite},
		{"mkdir + query -> write", "fs.mkdir", "query", mcpAccessWrite},
		{"symlink + query -> write", "fs.symlink", "query", mcpAccessWrite},
		{"enqueue + query -> write", "queue.enqueue", "query", mcpAccessWrite},
		{"register + query -> write", "svc.register", "query", mcpAccessWrite},
		{"disable_user + query -> write", "svc.disable_user", "query", mcpAccessWrite},
		{"replace_doc + query -> write", "db.replace_doc", "query", mcpAccessWrite},

		// --- Newly-added read verbs still classify as read ---
		{"download -> read", "files.download", "execute", mcpAccessRead},
		{"get_status -> read", "svc.get_status", "execute", mcpAccessRead},

		// --- write-wins still fires when a mutating verb pairs with a new read
		//     verb (R3 round 2: change/toggle are write, so these block). ---
		{"change_status + query -> write", "svc.change_status", "query", mcpAccessWrite},
		{"toggle_status + query -> write", "svc.toggle_status", "query", mcpAccessWrite},
		{"explain_change -> write", "svc.explain_change", "execute", mcpAccessWrite},
		{"activate + query -> write", "svc.activate", "query", mcpAccessWrite},
		{"submit_order + query -> write", "svc.submit_order", "query", mcpAccessWrite},

		// --- Tokens that merely CONTAIN a verb substring must NOT misclassify
		//     (word-boundary tokenisation, not substring match). ---
		{"get_settings -> read (not 'set')", "svc.get_settings", "execute", mcpAccessRead},
		{"list_commits -> read (not 'commit')", "git.list_commits", "execute", mcpAccessRead},
		{"describe_deployment -> read (not 'deploy')", "svc.describe_deployment", "execute", mcpAccessRead},

		// --- Connector prefix verb must NOT mask the method ---
		{"search connector, index method (unknown verb) honors op", "search.index_document", "query", mcpAccessRead},
		{"search connector, write method", "search.write_document", "query", mcpAccessWrite},

		// --- Inconclusive method name defers to operation ---
		{"unknown verb + op=query -> read", "svc.frobnicate", "query", mcpAccessRead},
		{"unknown verb + op=execute -> write", "svc.frobnicate", "execute", mcpAccessWrite},
		{"unknown verb + op empty -> write (default-deny)", "svc.frobnicate", "", mcpAccessWrite},
		{"unknown verb + op garbage -> write (default-deny)", "svc.frobnicate", "wat", mcpAccessWrite},

		// --- Operation case-insensitive ---
		{"op QUERY uppercase -> read", "svc.frobnicate", "QUERY", mcpAccessRead},
		{"op  query  whitespace -> read", "svc.frobnicate", "  query  ", mcpAccessRead},

		// --- Separators: slash and colon method extraction ---
		{"tools/execute slash", "tools/execute", "", mcpAccessWrite},
		{"tools/list slash", "tools/list", "", mcpAccessRead},
		{"colon namespace write", "ns:create", "", mcpAccessWrite},

		// --- Bare names without a connector prefix ---
		{"bare Read", "Read", "execute", mcpAccessRead},
		{"bare Write", "Write", "execute", mcpAccessWrite},

		// --- Empty connector type defers to operation ---
		{"empty connector + query -> read", "", "query", mcpAccessRead},
		{"empty connector + execute -> write", "", "execute", mcpAccessWrite},
		{"empty connector + empty op -> write (default-deny)", "", "", mcpAccessWrite},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMCPCall(tc.connectorType, tc.operation); got != tc.want {
				t.Errorf("classifyMCPCall(%q, %q) = %q, want %q", tc.connectorType, tc.operation, got, tc.want)
			}
		})
	}
}

// TestStatementIsWritePath is the authoritative spec for the resources/query
// statement classifier (the third write-capable MCP plane). It is fail-closed:
// an empty or unrecognised statement is a write (blocked).
func TestStatementIsWritePath(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		wantWrite bool
	}{
		// --- read SQL ---
		{"select", "SELECT 1", false},
		{"select lower", "select id from users", false},
		{"select leading whitespace", "   SELECT * FROM t", false},
		{"show", "SHOW TABLES", false},
		{"explain", "EXPLAIN SELECT 1", false},
		{"describe", "DESCRIBE users", false},
		{"values", "VALUES (1),(2)", false},
		{"read CTE", "WITH x AS (SELECT 1) SELECT * FROM x", false},
		// --- write SQL (the vulnerability) ---
		{"delete", "DELETE FROM t", true},
		{"delete lower", "delete from t where 1=1", true},
		{"update", "UPDATE t SET x=1", true},
		{"insert", "INSERT INTO t VALUES (1)", true},
		{"drop", "DROP TABLE t", true},
		{"truncate", "TRUNCATE t", true},
		{"alter", "ALTER TABLE t ADD COLUMN c int", true},
		{"create", "CREATE TABLE t (id int)", true},
		{"merge", "MERGE INTO t USING s ON ...", true},
		{"grant", "GRANT ALL ON t TO u", true},
		// --- data-modifying CTE must be caught ---
		{"data-modifying CTE", "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", true},
		{"CTE insert", "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x", true},
		// --- comment-hidden write must be caught (fail-closed) ---
		{"line-comment hidden delete", "-- harmless\nDELETE FROM t", true},
		{"block-comment hidden delete", "/* x */ DELETE FROM t", true},
		{"unterminated block comment", "/* never ends DELETE FROM t", true},
		// --- API-connector operation names (statement = operation) ---
		{"api search op -> read", "search_flights", false},
		{"api get op -> read", "get_booking", false},
		{"api create op -> write", "create_booking", true},
		{"api delete op -> write", "delete_booking", true},
		// --- stacked / multi-statement batches (R3 round-3 BLOCKER): a read-led
		//     batch with a trailing write must be blocked; SQL connectors run the
		//     whole batch. ---
		{"stacked select;delete -> write", "SELECT 1; DELETE FROM t", true},
		{"stacked select;update -> write", "SELECT 1; UPDATE t SET x=1", true},
		{"stacked two selects -> write (multi blocked outright)", "SELECT 1; SELECT 2", true},
		{"stacked with trailing whitespace stmt", "SELECT 1;   DROP TABLE t  ", true},
		{"trailing semicolon only -> read (single stmt)", "SELECT 1;", false},
		{"trailing semicolon + whitespace -> read", "SELECT 1;   ", false},
		{"trailing semicolon + comment -> read", "SELECT 1; -- done", false},
		{"semicolon inside string literal -> read", "SELECT ';' AS s", false},
		{"semicolon inside string then real stmt -> write", "SELECT 'a;b'; DELETE FROM t", true},
		{"comment-hidden stacked delete", "SELECT 1 /* ; DELETE */ ; DELETE FROM t", true},

		// --- dollar-quoting (R3 round-4 BLOCKER): rejected outright, fail-closed.
		//     A `'` inside a $$ body desyncs a naive '-splitter and hides a real
		//     top-level `;`, so any dollar-quote -> block. ---
		{"dollar-quote desync stacked DELETE", "SELECT $$ ' $$ ; DELETE FROM t -- '", true},
		{"dollar-quote simple", "SELECT $$abc$$", true},
		{"dollar-quote tagged", "SELECT $tag$abc$tag$", true},
		{"dollar-quote function body write", "CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END $$ LANGUAGE plpgsql", true},
		// Postgres parameter placeholders ($1, $2) are NOT dollar-quotes and must
		// not be falsely blocked.
		{"param placeholders -> read", "SELECT id FROM t WHERE a = $1 AND b = $2", false},

		// --- SELECT INTO (R3 round-4): SELECT ... INTO <table> creates a table. ---
		{"select into -> write", "SELECT * INTO t2 FROM t1", true},
		{"select into lower", "select a, b into new_t from old_t", true},
		{"select into with CTE -> write", "WITH x AS (SELECT 1) SELECT * INTO t2 FROM x", true},
		{"into inside string literal -> read (not a real INTO)", "SELECT 'walk into a bar' AS joke", false},
		{"select without into -> read", "SELECT * FROM t1", false},

		// --- EXPLAIN ANALYZE / ANALYSE EXECUTES the embedded statement (R3 round-5).
		//     Plain EXPLAIN only plans (no execution) and stays read. ---
		{"explain analyze delete -> write", "EXPLAIN ANALYZE DELETE FROM t", true},
		{"explain (analyze, buffers) delete -> write", "EXPLAIN (ANALYZE, BUFFERS) DELETE FROM users", true},
		{"explain analyse british truncate -> write", "EXPLAIN ANALYSE TRUNCATE t", true},
		{"explain analyze select -> write (still executes)", "EXPLAIN ANALYZE SELECT * FROM t", true},
		{"plain explain select -> read", "EXPLAIN SELECT 1", false},
		{"explain format json select -> read", "EXPLAIN (FORMAT JSON) SELECT 1", false},
		{"explain with ANALYZE inside a string -> read", "EXPLAIN SELECT 'ANALYZE'", false},

		// --- fail-closed cases ---
		{"empty -> write", "", true},
		{"whitespace only -> write", "   ", true},
		{"only a comment -> write", "-- just a comment", true},
		{"unknown opaque token -> write", "frobnicate the thing", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := statementIsWritePath(tc.statement); got != tc.wantWrite {
				t.Errorf("statementIsWritePath(%q) = %v, want %v", tc.statement, got, tc.wantWrite)
			}
		})
	}
}

// TestMaskSQLLiteralsAndComments pins the masker the statement classifier relies
// on: literal/comment content (and a `;` or keyword inside it) is blanked, a
// real top-level `;` survives, escaping is handled, and an unterminated
// literal/comment is reported.
func TestMaskSQLLiteralsAndComments(t *testing.T) {
	tests := []struct {
		name          string
		in            string
		wantUnterm    bool
		wantSemicolon bool // does a top-level ';' survive in the masked text?
	}{
		{"plain", "SELECT 1", false, false},
		{"single-quote blanks ; inside", "SELECT ';'", false, false},
		{"escaped single quote", "SELECT 'a''b'", false, false},
		{"double-quote ident blanks ; inside", "SELECT \";\"", false, false},
		{"escaped double quote", "SELECT \"a\"\"b\"", false, false},
		{"line comment blanks ; inside", "SELECT 1 -- ; DELETE", false, false},
		{"block comment blanks ; inside", "SELECT/* ; DELETE */1", false, false},
		{"top-level semicolon survives", "SELECT 1; DELETE", false, true},
		{"semicolon in string gone, top-level survives", "SELECT 'a;b'; DELETE", false, true},
		{"unterminated single quote", "SELECT 'oops", true, false},
		{"unterminated double quote", "SELECT \"oops", true, false},
		{"unterminated block comment", "SELECT /* oops", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, unterm := maskSQLLiteralsAndComments(tc.in)
			if unterm != tc.wantUnterm {
				t.Errorf("maskSQLLiteralsAndComments(%q) unterminated=%v, want %v", tc.in, unterm, tc.wantUnterm)
			}
			if len([]rune(got)) != len([]rune(tc.in)) {
				t.Errorf("masked rune-length %d != input %d (must preserve structure)", len([]rune(got)), len([]rune(tc.in)))
			}
			if strings.Contains(got, ";") != tc.wantSemicolon {
				t.Errorf("maskSQLLiteralsAndComments(%q) = %q; top-level ';' present=%v, want %v", tc.in, got, strings.Contains(got, ";"), tc.wantSemicolon)
			}
		})
	}
}

// TestSplitIdentifier locks the tokenizer behaviour the classifier relies on,
// including camelCase, PascalCase, acronym, and separator handling.
func TestSplitIdentifier(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"Bash", []string{"bash"}},
		{"create_record", []string{"create", "record"}},
		{"getUserList", []string{"get", "user", "list"}},
		{"HTTPGet", []string{"http", "get"}},
		{"read-or-write", []string{"read", "or", "write"}},
		{"delete2records", []string{"delete2records"}},
		{"", nil},
		{"___", nil},
		{"ALLCAPS", []string{"allcaps"}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := splitIdentifier(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitIdentifier(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestTokenizeMethod verifies the method segment is extracted from the last
// separator so connector prefixes never participate in classification.
func TestTokenizeMethod(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"claude_code.Write", []string{"write"}},
		{"search.index_document", []string{"index", "document"}},
		{"tools/execute", []string{"execute"}},
		{"ns:create", []string{"create"}},
		{"Read", []string{"read"}},
		{"a.b.c.getThing", []string{"get", "thing"}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := tokenizeMethod(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("tokenizeMethod(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
