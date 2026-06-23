// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"regexp"
	"strings"
	"unicode"
)

// =============================================================================
// Read-Only Enforcement Posture (#2720, epic #2716, design-partner PoC)
//
// A turnkey, one-config governance posture that blocks every WRITE-PATH MCP
// tool call at the gate before it reaches an internal system, while letting
// READ-PATH calls through. It needs no per-MCP-server code and no per-tool
// policy authoring: a single env toggle activates a deployment-wide read-only
// boundary.
//
// Why a posture FLAG rather than a seeded DB policy:
//   - The read/write distinction is a semantic property of the tool call
//     (its method/operation verb), not a regex match on the statement. The
//     static-policy engine matches CONTENT (SQLi, PII, dangerous patterns); it
//     has no notion of "is this call a read or a write". Seeding a row whose
//     condition keys on a tool name would NOT enforce anything, because
//     condition fields are not allowlist-validated and, more importantly, the
//     evaluator does not classify read-vs-write. Enforcement therefore MUST be
//     wired into the gate (this file), not assumed from a seed.
//   - A single boolean env is the cleanest "one-config enable" and avoids a
//     migration entirely (so there is no migration-number coupling).
//
// Enforcement point: mcpToolCheckPolicy (the MCP-server check_policy gate in
// mcp_server_handler.go), the request-phase boundary every plugin pre-tool
// hook flows through. When the posture is on and a call classifies as
// write-path, the gate returns a blocked decision (canonical "blocked" verdict,
// audited) before any other policy evaluation or session-override flow runs.
// The posture is a deployment-wide safety boundary and is intentionally NOT
// overridable via the per-policy session-override (ADR-044) flow.
// =============================================================================

// EnvMCPReadOnly is the single env toggle that activates the read-only posture
// for the MCP gate. Accepts true/1/yes (on) or false/0/no (off, default).
//
// Example: MCP_READ_ONLY=true blocks every write-path MCP tool call.
const EnvMCPReadOnly = "MCP_READ_ONLY"

// readOnlyPosturePolicyID is the stable synthetic policy identifier reported in
// the blocked_by field and the audit_logs policy_ids when the read-only posture
// denies a call. It is not a DB row, it names the posture so operators can
// recognise a read-only block in the decisions feed and docs.
const readOnlyPosturePolicyID = "sys_mcp_read_only_posture"

// readOnlyPostureEnabled reports whether the read-only posture is active.
// Reads MCP_READ_ONLY via the shared parseBoolEnv helper (default false), so
// behaviour is unchanged for every deployment that does not opt in.
func readOnlyPostureEnabled() bool {
	return parseBoolEnv(EnvMCPReadOnly, false)
}

// mcpAccessClass is the read/write classification of an MCP tool call.
type mcpAccessClass string

const (
	// mcpAccessRead is a read-path call (MCP Resources pattern: query/get/list).
	mcpAccessRead mcpAccessClass = "read"
	// mcpAccessWrite is a write-path call (MCP Tools pattern: execute/create/update/delete).
	mcpAccessWrite mcpAccessClass = "write"
)

// readVerbs are method-name tokens that mark a read-path (side-effect-free)
// operation. Mirrors the connector base contract (Query == MCP Resources ==
// read-only) and common tool naming across MCP servers. Kept conservative on
// purpose: write verbs always win (see classifyMCPCall), so a read verb only
// matters when no write verb is present.
var readVerbs = map[string]struct{}{
	"read": {}, "get": {}, "list": {}, "search": {}, "query": {}, "fetch": {},
	"describe": {}, "find": {}, "grep": {}, "glob": {}, "view": {}, "show": {},
	"head": {}, "tail": {}, "cat": {}, "select": {}, "count": {}, "stat": {},
	"lookup": {}, "ls": {}, "peek": {}, "inspect": {}, "scan": {}, "browse": {},
	"check": {}, "exists": {}, "info": {}, "summary": {}, "download": {},
	"preview": {}, "status": {}, "watch": {}, "poll": {}, "explain": {},
}

// writeVerbs are method-name tokens that mark a write-path (mutating or
// side-effecting) operation. Mirrors the connector base contract (Execute ==
// MCP Tools == write/command) plus the broad family of mutating verbs seen
// across MCP servers and REST/CRUD tooling. Bash/shell/run/exec are treated as
// write because an arbitrary command can mutate state, so a read-only posture
// must fail safe and block them.
//
// This list is intentionally broad: any verb here forces a block regardless of
// the caller-supplied operation field, so adding a verb here only ever makes the
// posture stricter. A genuinely novel write verb not listed here still fails
// safe via the unknown-name default-deny in classifyMCPCall when operation is
// execute/empty; pair the posture with the connector allowlist
// (MCP_STATIC_POLICIES_CONNECTORS) for a guarantee that does not depend on the
// caller's declared operation. See docs/governance/read-only-posture.md.
var writeVerbs = map[string]struct{}{
	"write": {}, "edit": {}, "create": {}, "update": {}, "delete": {},
	"insert": {}, "drop": {}, "put": {}, "post": {}, "patch": {}, "remove": {},
	"rm": {}, "exec": {}, "execute": {}, "run": {}, "bash": {}, "shell": {},
	"sh": {}, "command": {}, "mv": {}, "move": {}, "copy": {}, "cp": {},
	"rename": {}, "modify": {}, "set": {}, "push": {}, "commit": {}, "send": {},
	"mutate": {}, "truncate": {}, "alter": {}, "upsert": {}, "save": {},
	"append": {}, "kill": {}, "terminate": {}, "deploy": {}, "apply": {},
	"call": {}, "invoke": {}, "trigger": {}, "publish": {}, "destroy": {},
	// Mutating verbs the first cut omitted (R3 round 1):
	"upload": {}, "add": {}, "merge": {}, "replace": {}, "transfer": {},
	"grant": {}, "revoke": {}, "register": {}, "unregister": {}, "provision": {},
	"deprovision": {}, "enable": {}, "disable": {}, "reset": {}, "cancel": {},
	"approve": {}, "reject": {}, "charge": {}, "refund": {}, "mkdir": {},
	"rmdir": {}, "symlink": {}, "link": {}, "unlink": {}, "enqueue": {},
	"dequeue": {}, "flush": {}, "sync": {}, "import": {}, "restore": {},
	"rollback": {}, "migrate": {}, "seed": {}, "attach": {}, "detach": {},
	"assign": {}, "unassign": {}, "archive": {}, "purge": {}, "expire": {},
	"schedule": {}, "dispatch": {}, "emit": {}, "notify": {}, "store": {},
	"clear": {}, "drain": {}, "ack": {}, "acknowledge": {}, "close": {},
	"start": {}, "stop": {}, "restart": {}, "pause": {}, "resume": {},
	"scale": {}, "rotate": {}, "issue": {}, "mint": {}, "sign": {},
	"revert": {}, "undo": {}, "redo": {}, "lock": {}, "unlock": {},
	// Further mutating verbs (R3 round 2): closes the read-verb-expansion
	// micro-regression (change/toggle paired with status/explain) and shrinks
	// the unknown-verb residual.
	"toggle": {}, "change": {}, "increment": {}, "decrement": {},
	"activate": {}, "deactivate": {}, "submit": {}, "confirm": {},
	"decline": {}, "allocate": {}, "reserve": {}, "release": {},
	"acquire": {}, "bind": {}, "connect": {}, "disconnect": {},
	"subscribe": {}, "unsubscribe": {}, "upgrade": {}, "downgrade": {},
	"install": {}, "uninstall": {}, "build": {}, "generate": {},
	"process": {}, "persist": {}, "share": {}, "invite": {},
	"promote": {}, "demote": {}, "fork": {}, "clone": {},
	"snapshot": {}, "backup": {}, "checkout": {}, "tag": {},
}

// classifyMCPCall classifies an MCP tool call as read-path or write-path.
//
// The rule is deterministic and documented (docs/governance/read-only-posture.md):
//
//  1. Extract the METHOD name: the segment of connectorType after the last of
//     '.', '/' or ':' (e.g. "claude_code.Write" -> "Write", "tools/execute" ->
//     "execute"). Connector/prefix tokens are deliberately ignored so a
//     connector NAMED with a read verb (e.g. "search.index_record") cannot mask
//     a write method.
//  2. Tokenise the method into lowercase words, splitting on separators
//     (_ - space) AND camelCase boundaries (getUser -> [get, user]).
//  3. If ANY token is a write verb -> write. (Write wins over read: a method
//     like "read_or_write" is treated as a write, the fail-safe choice for a
//     read-only posture.)
//  4. Else if ANY token is a read verb -> read.
//  5. Else fall back to the explicit operation field: "query" -> read; anything
//     else ("execute", "", or an unrecognised value) -> write. Unknown calls
//     default to WRITE (default-deny) so a write can never slip through an
//     unclassified name.
func classifyMCPCall(connectorType, operation string) mcpAccessClass {
	tokens := tokenizeMethod(connectorType)

	hasWrite := false
	hasRead := false
	for _, tok := range tokens {
		if _, ok := writeVerbs[tok]; ok {
			hasWrite = true
		}
		if _, ok := readVerbs[tok]; ok {
			hasRead = true
		}
	}
	switch {
	case hasWrite:
		// Write wins over read, fail safe under a read-only posture.
		return mcpAccessWrite
	case hasRead:
		return mcpAccessRead
	}

	// Inconclusive name: defer to the explicit operation field.
	if strings.EqualFold(strings.TrimSpace(operation), "query") {
		return mcpAccessRead
	}
	// "execute", empty, or anything unrecognised -> default-deny (write).
	return mcpAccessWrite
}

// sqlReadKeywords are the leading SQL keywords that begin a read-only statement.
// A statement on the resources/query plane is allowed only when it begins with
// one of these (or a read-verb-named API operation); everything else fails
// closed to a block under the read-only posture.
var sqlReadKeywords = map[string]struct{}{
	"SELECT": {}, "SHOW": {}, "EXPLAIN": {}, "DESCRIBE": {}, "DESC": {},
	"PRAGMA": {}, "VALUES": {}, "TABLE": {}, "FETCH": {},
}

// sqlCTEWriteKeywords are the data-modifying keywords that can appear inside a
// `WITH ... ` common-table expression (Postgres allows data-modifying CTEs, e.g.
// `WITH x AS (DELETE FROM t RETURNING *) SELECT ...`). A WITH statement that
// mentions any of these is treated as write-path.
var sqlCTEWriteKeywords = map[string]struct{}{
	"INSERT": {}, "UPDATE": {}, "DELETE": {}, "MERGE": {}, "DROP": {},
	"CREATE": {}, "ALTER": {}, "TRUNCATE": {}, "REPLACE": {}, "UPSERT": {},
	"GRANT": {}, "REVOKE": {}, "CALL": {},
}

// statementIsWritePath classifies a resources/query statement as write-path.
//
// The resources/query plane (mcpQueryHandler) hands a caller-supplied statement
// straight to connector.Query, and SQL connectors execute it verbatim, so a
// `DELETE`/`UPDATE`/`DROP`/... mutates even though the plane's operation is the
// fixed "query" (which classifyMCPCall would read as a read). This classifies
// the STATEMENT itself and is FAIL-CLOSED: an empty or unrecognised statement
// is treated as write so it is blocked under the read-only posture.
//
// Rules:
//  1. Strip leading SQL comments + whitespace; empty -> write (fail-closed).
//  2. `WITH ...` -> write if the statement mentions any data-modifying keyword
//     (data-modifying CTE), else read.
//  3. Leading keyword in sqlReadKeywords (SELECT/SHOW/EXPLAIN/...) -> read.
//  4. Otherwise treat the leading token as an operation/tool name and verb-
//     tokenise it (reusing the read/write verb vocabulary): a write verb -> write
//     (this also catches INSERT/UPDATE/DELETE/DROP/ALTER/MERGE/CREATE/...);
//     a read verb -> read (e.g. an API connector's `search_flights`); anything
//     else -> write (fail-closed).
//
// dollarQuoteRe matches a Postgres dollar-quote delimiter ($$ or $tag$). A
// dollar-quoted body can contain arbitrary text including `'`, `;`, and `--`,
// which would desync any `'`/comment-based splitter and let a stacked write hide
// (e.g. `SELECT $$ ' $$ ; DELETE ...` runs the DELETE). Rather than track tag
// spans, the read-only posture rejects any statement that contains a dollar-quote
// outright (fail-closed), dollar-quoting in a read query is rare. Postgres
// parameter placeholders ($1, $2) do not match (no trailing `$`).
var dollarQuoteRe = regexp.MustCompile(`\$[A-Za-z0-9_]*\$`)

func statementIsWritePath(statement string) bool {
	// Dollar-quoting: not parsed; reject outright (fail-closed). See dollarQuoteRe.
	if dollarQuoteRe.MatchString(statement) {
		return true
	}

	// Mask string-literal and comment CONTENT to spaces so a `;` or a keyword
	// hidden inside one is neither mistaken for a separator nor able to fake a
	// keyword, and a real top-level `;` is never swallowed. An unterminated
	// literal/comment (a classic splitter-evasion shape) fails closed.
	masked, unterminated := maskSQLLiteralsAndComments(statement)
	if unterminated {
		return true
	}

	// Stacked / multi-statement batch (e.g. "SELECT 1; DELETE FROM t"): a SQL
	// connector runs the whole batch, so a read-led batch can still carry a
	// trailing write. Top-level statements are the non-blank `;`-separated masked
	// segments; >1 is rejected outright, 0 (empty/comment-only) fails closed.
	realSegments := 0
	for _, seg := range strings.Split(masked, ";") {
		if strings.TrimSpace(seg) != "" {
			realSegments++
		}
	}
	if realSegments != 1 {
		return true
	}

	// Single statement. Classify on the MASKED text (literals already blanked, so
	// a keyword inside a string can't false-positive). The leading verb of a SQL
	// statement / the operation name of an API connector is never inside a string,
	// so the masked leading token equals the real one.
	trimmed := strings.TrimSpace(masked)
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return true // fail-closed: nothing classifiable
	}
	firstUpper := strings.ToUpper(fields[0])
	upTokens := strings.FieldsFunc(strings.ToUpper(trimmed), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	if firstUpper == "WITH" {
		// Data-modifying CTE, or a CTE feeding a SELECT INTO, is a write.
		for _, w := range upTokens {
			if _, ok := sqlCTEWriteKeywords[w]; ok {
				return true
			}
			if w == "INTO" {
				return true
			}
		}
		return false
	}

	if _, ok := sqlReadKeywords[firstUpper]; ok {
		// SELECT ... INTO <table> CREATES a table (a write), so a top-level INTO
		// turns a SELECT-led statement into a write.
		if firstUpper == "SELECT" {
			for _, w := range upTokens {
				if w == "INTO" {
					return true
				}
			}
		}
		// EXPLAIN ANALYZE (and British ANALYSE) actually EXECUTES the embedded
		// statement, so `EXPLAIN ANALYZE DELETE FROM t` permanently mutates. Plain
		// EXPLAIN only plans (no execution) and stays read. Treat an EXPLAIN that
		// carries a top-level ANALYZE/ANALYSE as a write.
		if firstUpper == "EXPLAIN" {
			for _, w := range upTokens {
				if w == "ANALYZE" || w == "ANALYSE" {
					return true
				}
			}
		}
		return false
	}

	// Not a leading read keyword: verb-tokenise the leading token. A write verb
	// (which includes insert/update/delete/drop/alter/merge/create/...) blocks;
	// a read verb (e.g. search/get/list) allows; unknown fails closed.
	tokens := splitIdentifier(fields[0])
	for _, t := range tokens {
		if _, ok := writeVerbs[t]; ok {
			return true
		}
	}
	for _, t := range tokens {
		if _, ok := readVerbs[t]; ok {
			return false
		}
	}
	return true // unclassifiable -> fail-closed block
}

// maskSQLLiteralsAndComments replaces the CONTENT (and delimiters) of SQL string
// literals and comments with spaces, preserving everything else, and reports
// whether a string or block comment was left UNTERMINATED. The result has the
// same top-level structure (a real `;` outside any literal/comment survives; a
// `;` inside one becomes a space), so it can be split on `;` and tokenised
// without a literal/comment hiding a separator or faking a keyword.
//
// Handles single-quoted strings (with `”` escaping), double-quoted identifiers
// (with `""` escaping), line comments (`--`), and block comments (`/* */`).
// Dollar-quoting is intentionally NOT handled here; callers reject it earlier.
func maskSQLLiteralsAndComments(s string) (masked string, unterminated bool) {
	runes := []rune(s)
	n := len(runes)
	out := make([]rune, 0, n)
	for i := 0; i < n; {
		c := runes[i]
		switch {
		case c == '-' && i+1 < n && runes[i+1] == '-':
			// line comment to end of line
			for i < n && runes[i] != '\n' {
				out = append(out, ' ')
				i++
			}
		case c == '/' && i+1 < n && runes[i+1] == '*':
			out = append(out, ' ', ' ')
			i += 2
			closed := false
			for i < n {
				if runes[i] == '*' && i+1 < n && runes[i+1] == '/' {
					out = append(out, ' ', ' ')
					i += 2
					closed = true
					break
				}
				out = append(out, ' ')
				i++
			}
			if !closed {
				unterminated = true
			}
		case c == '\'':
			out = append(out, ' ')
			i++
			closed := false
			for i < n {
				if runes[i] == '\'' {
					if i+1 < n && runes[i+1] == '\'' {
						out = append(out, ' ', ' ')
						i += 2
						continue
					}
					out = append(out, ' ')
					i++
					closed = true
					break
				}
				out = append(out, ' ')
				i++
			}
			if !closed {
				unterminated = true
			}
		case c == '"':
			out = append(out, ' ')
			i++
			closed := false
			for i < n {
				if runes[i] == '"' {
					if i+1 < n && runes[i+1] == '"' {
						out = append(out, ' ', ' ')
						i += 2
						continue
					}
					out = append(out, ' ')
					i++
					closed = true
					break
				}
				out = append(out, ' ')
				i++
			}
			if !closed {
				unterminated = true
			}
		default:
			out = append(out, c)
			i++
		}
	}
	return string(out), unterminated
}

// tokenizeMethod returns the lowercase word tokens of the method name embedded
// in connectorType. It takes the segment after the last '.', '/' or ':' and
// splits it on separators and camelCase boundaries.
func tokenizeMethod(connectorType string) []string {
	name := connectorType
	if i := strings.LastIndexAny(name, "./:"); i >= 0 {
		name = name[i+1:]
	}
	return splitIdentifier(name)
}

// splitIdentifier breaks an identifier into lowercase word tokens, splitting on
// non-alphanumeric separators and at camelCase / PascalCase boundaries.
//
// Examples:
//
//	"Bash"          -> ["bash"]
//	"create_record" -> ["create", "record"]
//	"getUserList"   -> ["get", "user", "list"]
//	"HTTPGet"       -> ["http", "get"]
func splitIdentifier(s string) []string {
	var tokens []string
	var cur []rune
	runes := []rune(s)

	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}

	for i, r := range runes {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			// Separator (_, -, space, etc.), end the current token.
			flush()
		case unicode.IsUpper(r):
			// camelCase boundary: a lower/digit immediately before an upper
			// (getUser), or an upper followed by a lower after a run of uppers
			// (HTTPGet -> HTTP | Get).
			if i > 0 {
				prev := runes[i-1]
				if unicode.IsLower(prev) || unicode.IsDigit(prev) {
					flush()
				} else if unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
					flush()
				}
			}
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return tokens
}
