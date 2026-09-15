// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package legacyfreeze is the one definition of how a caller is told that a
// write to the legacy policy tables was refused by the v11 freeze.
//
// migrations/core/172 revoked write access on static_policies and
// dynamic_policies from the application roles (#3880). Postgres then refuses
// those writes with SQLSTATE 42501, and every route that still writes them has
// to answer that refusal as what it is - a retired write path with a named
// replacement - rather than as a server fault a caller will retry.
//
// WHY THIS IS A PACKAGE BOTH BINARIES IMPORT, AND NOT A FUNCTION IN EITHER.
// The classifier began in package orchestrator. The agent writes
// static_policies from its own system-policy routes and cannot import package
// orchestrator (the orchestrator imports the agent, so the edge would close a
// cycle), so its four write verbs kept answering a bare 500 (#4084). A copy in
// the agent would have fixed that and reopened the class: #4036 happened
// because a second route family served the same write through a different
// handler and nobody routed it through the answer, and #4088 was a third. One
// definition, imported by every surface, is the only arrangement in which a
// new surface cannot acquire its own opinion about the status, the code, the
// remedy or the classification.
//
// The census in writer_census_test.go is what stops a further surface from
// skipping the answer altogether: it derives every HTTP handler that can reach
// a write of either table and requires each to call Answer.
package legacyfreeze

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/lib/pq"

	logutil "axonflow/platform/shared/logger"
)

// ErrCode is what a caller gets when it tries to write the legacy policy
// tables.
//
// It is a distinct code rather than a reuse of the tier vocabulary because it
// is not a tier fact: no licence, edition or upgrade changes it. The legacy
// write path is retired for every caller on every edition, and the typed
// authoring route is where writes go now.
const ErrCode = "LEGACY_POLICY_WRITE_FROZEN"

// TypedAuthoringRoute is the route the refusal sends a caller to.
//
// The orchestrator registers it as TypedAuthoringRoutePrefix, and a test in
// that package requires the two to be equal: this constant is a claim about a
// route another package serves, and a refusal naming a route that is not
// served sends an operator to a 404.
const TypedAuthoringRoute = "/api/v1/typed-policies"

// Message names the remedy. A refusal that says only "forbidden" leaves an
// operator to guess, and the guess most of them will make - a permissions or
// licence problem - is wrong in a way that costs a support round trip.
const Message = "The legacy policy tables are read-only in v11: " +
	"migrations/core/172 revoked write access from the application role, and this endpoint writes them. " +
	"Author policies through the typed authoring route at " + TypedAuthoringRoute + " instead. " +
	"Reads on this endpoint are unaffected."

// OverrideMessage names the remedy for every policy override write (PRD v11
// §1.5): the per-policy override routes and, since #4252, the ADR-044 session
// override routes. core/172 does not revoke policy_overrides, so each writer
// refuses at the handler, before any row is written, and there is no database
// error to classify.
const OverrideMessage = "Policy overrides are retired in v11: " +
	"a policy is enabled, disabled or re-actioned in the organization's typed document (a shipped system control in its system_controls section) " +
	"through the typed authoring route at " + TypedAuthoringRoute + ". " +
	"Reads on this endpoint are unaffected."

// insufficientPrivilege is SQLSTATE 42501.
const insufficientPrivilege = "42501"

// frozenTables are the tables core/172 made read-only to the application roles.
var frozenTables = []string{"static_policies", "dynamic_policies"}

// IsFrozen reports whether err is the core/172 freeze.
//
// # Why this cannot key on the SQLSTATE alone, which is the whole subtlety
//
// 42501 is insufficient_privilege, and Postgres raises it for TWO different
// things on these tables:
//
//   - the REVOKE in core/172 - the role may not write the table at all, which
//     is this freeze and is a permanent, correct refusal to report to a caller;
//   - a row-level security WITH CHECK violation - the row's org_id does not
//     match app.current_org_id, which is a BUG in our own wrapping (a missing
//     or wrong GUC) and must keep surfacing as a server error.
//
// Reporting the second as "use the typed authoring route" would tell an
// operator to change their integration in response to a defect on our side,
// and would hide an org-scoping bug behind a retirement notice. The two are
// distinguishable only by message text: Postgres words the privilege failure as
// `permission denied for table X` (and `for relation X` on older servers) and
// the RLS failure as `new row violates row-level security policy for table X`.
//
// # It matches the privilege cause POSITIVELY, and that direction matters
//
// The alternative - match 42501 and exclude the RLS wording - fails OPEN for
// any third 42501 shape we have not met: an unknown one would be reported to
// the caller as the freeze. Matching `permission denied for` positively means
// an unrecognised 42501 falls through to the caller's existing INTERNAL_ERROR,
// which is the safe direction for a cause we cannot name.
//
// # It also names the TABLES, so the next freeze does not inherit this answer
//
// `permission denied for table X` is the same sentence whichever table X is,
// and the routes that write these two tables write others too - the
// orchestrator's repository writes policy_versions and the agent's writes
// static_policy_versions. A classifier keyed on the message SHAPE alone would
// answer "author through the typed policy route" for any table a future
// migration freezes, which is wrong the moment that table's write path is
// something else. So the subject is checked as well as the shape: a privilege
// refusal on a table this freeze does not cover falls through to
// INTERNAL_ERROR.
func IsFrozen(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	if string(pqErr.Code) != insufficientPrivilege {
		return false
	}
	// pq.Error.Table is not populated for a privilege refusal, so the table is
	// read from the message, which is where Postgres puts it.
	//
	// ANCHORED ON `for table <name>` RATHER THAN TWO INDEPENDENT SUBSTRING
	// TESTS. A bare Contains("permission denied for table") plus a separate
	// Contains(frozenTable) would also match a message that mentions a frozen
	// table for some unrelated reason - in a constraint name, a detail line or
	// a statement echo - which is a refusal this classifier has no business
	// claiming. Requiring the name to sit in the subject position makes the
	// match about what Postgres refused.
	for _, t := range frozenTables {
		if refusalNamesTableAsSubject(pqErr.Message, t) {
			return true
		}
	}
	return false
}

// refusalNamesTableAsSubject reports whether msg is a privilege refusal whose
// SUBJECT is exactly table t.
//
// THE NAME MUST END WHERE THE TABLE NAME ENDS. A prefix test is not subject
// position: `permission denied for table dynamic_policies_archive` starts with
// `...for table dynamic_policies`, so a Contains test would classify a refusal
// on a DIFFERENT table as this freeze. The name must be followed by a
// non-identifier byte or the end of the message, and a longer name sharing the
// prefix does not stop the scan from finding a genuine match later on.
func refusalNamesTableAsSubject(msg, t string) bool {
	for _, lead := range []string{"permission denied for table ", "permission denied for relation "} {
		needle := lead + t
		for from := 0; ; {
			i := strings.Index(msg[from:], needle)
			if i < 0 {
				break
			}
			end := from + i + len(needle)
			if end == len(msg) || !isIdentifierByte(msg[end]) {
				return true
			}
			// A longer name shares this prefix; keep looking for a real match.
			from += i + 1
		}
	}
	return false
}

// isIdentifierByte reports whether b can continue an unquoted Postgres
// identifier, which is what decides where a table name ends in these messages.
func isIdentifierByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// ErrorWriter renders an error envelope. Each surface passes its own, because
// the envelopes genuinely differ - the orchestrator's policy routes render a
// typed PolicyAPIError, its deprecated family an untyped map, its template
// routes a TemplateAPIError, and the agent a map whose code is otherwise the
// numeric status - and unifying them would change the response shape of every
// other route those writers serve.
type ErrorWriter func(w http.ResponseWriter, status int, code, message string)

// Answer answers the freeze and reports whether it did.
//
// It is called on a write route's error path, AFTER the route's own named
// refusals (validation, tier, not-found) and BEFORE its generic 500, so each
// of those keeps its own rendering and an unclassified error keeps today's.
//
// The writer is passed in rather than the handler, so a new caller cannot
// quietly acquire its own opinion about the status code, the error code or the
// remedy text: those three are fixed here, and only the envelope is the
// caller's.
func Answer(w http.ResponseWriter, err error, logPrefix, op, tenantID string, write ErrorWriter) bool {
	if !IsFrozen(err) {
		return false
	}
	log.Printf("[%s] %s refused by the core/172 legacy policy freeze for tenant %s: %v", logPrefix, op, tenantID, err)
	write(w, http.StatusConflict, ErrCode, Message)
	return true
}

// RefuseOverride answers a policy override write with the freeze, always.
// It is Answer's sibling for a write that reaches no frozen table: the status,
// the code and the remedy are fixed here, and only the envelope is the
// caller's.
func RefuseOverride(w http.ResponseWriter, logPrefix, op, tenantID string, write ErrorWriter) {
	log.Printf("[%s] %s refused: policy overrides are retired in v11 (tenant %s)", logPrefix, op, tenantID)
	write(w, http.StatusConflict, ErrCode, OverrideMessage)
}

// Querier is the one method MayWrite needs; *sql.DB, *sql.Conn and *sql.Tx
// all satisfy it.
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// MayWrite reports whether the connection q holds may INSERT into table, which
// must be one this freeze covers.
//
// # Ask the database, not the environment
//
// core/172 revokes the legacy tables' writes from the APPLICATION roles only;
// an owner-role deployment still writes (PRD v11 §5 item 5, the ADR-065
// amendment of 2026-09-08). AXONFLOW_DB_USE_APP_ROLE cannot say which of the
// two a pool is: it defaults to true, and ResolveAppRoleDSN falls back to the
// supplied owner DSN when no app-role URL is set, which is the ordinary
// docker-compose case. has_table_privilege answers for the connection held.
// The orchestrator's sample seed reasoned this out first and asks it here too.
//
// # Why INSERT alone
//
// core/172 revokes INSERT, UPDATE, DELETE and TRUNCATE together, and its down
// file restores SELECT, INSERT, UPDATE and DELETE together, so a connection
// holding one write privilege and not another is not a state either file
// produces.
//
// # Why the table is checked
//
// A caller asking about some other table would then answer this freeze's
// message for it, which is the mistake IsFrozen's subject anchor exists to
// prevent on the classification side.
func MayWrite(ctx context.Context, q Querier, table string) (bool, error) {
	if !isFrozenTable(table) {
		return false, fmt.Errorf("legacyfreeze: %q is not a table the core/172 freeze covers", table)
	}
	var may bool
	// $1::text selects has_table_privilege(text, text), which reads the name as
	// a possibly-qualified relation name, the same resolution a literal gets.
	if err := q.QueryRowContext(ctx, "SELECT has_table_privilege($1::text, 'INSERT')", table).Scan(&may); err != nil {
		return false, fmt.Errorf("checking INSERT privilege on %s: %w", table, err)
	}
	return may, nil
}

func isFrozenTable(table string) bool {
	for _, t := range frozenTables {
		if t == table {
			return true
		}
	}
	return false
}

// RefusedPrefix starts the one line Refuse logs per refused request. The line
// carries the organization, the tenant and the route, so the refusals are
// countable per organization from the service log (a metric filter or a grep
// on this string); it is a constant so a counter and the code cannot drift.
const RefusedPrefix = "[legacyfreeze] legacy write refused before its request body was read:"

// Refuse answers a legacy write with the freeze BEFORE the route reads the
// request, and always. It is RefuseOverride's sibling for a route whose write
// lands on a frozen table: the caller decides whether the freeze is in force
// for its connection (MayWrite), and Refuse fixes the status, the code and the
// remedy. The remedy is Message, the sentence Answer sends, so a route answers
// the same words whether it refused up front or the database refused the write.
//
// WHY BEFORE THE READ (#4237). Answer classifies the database's refusal of the
// write, so a body that failed the route's own validation never reached the
// write and was answered 500 instead of the freeze, on a deployment where no
// legacy write can succeed whatever the body says.
func Refuse(w http.ResponseWriter, r *http.Request, logPrefix, op, orgID, tenantID string, write ErrorWriter) {
	log.Printf("%s org=%s tenant=%s route=%s op=%s surface=%s", RefusedPrefix,
		logutil.Sanitize(orgID), logutil.Sanitize(tenantID),
		logutil.Sanitize(r.Method+" "+r.URL.Path), op, logPrefix)
	write(w, http.StatusConflict, ErrCode, Message)
}

// RefuseWhenRevoked answers a legacy write with the freeze BEFORE the route
// reads the request, when may reports that the connection the write would go
// through cannot write the frozen table, and reports whether it did (#4237).
// The routes that refuse before decode call it - the orchestrator's policy
// routes and template apply, and the agent's system-policy create, update and
// toggle - each with its own probe and its own envelope. DELETE takes no body
// and is answered by the classified refusal of its write (#4249).
//
// WHY AN UNANSWERED PROBE FALLS THROUGH RATHER THAN REFUSING. Where the freeze
// is in force the database still refuses the write itself, and Answer still
// classifies that refusal, so falling through can cost a malformed body the 409
// (it gets its 400) but can never let a frozen write succeed. Refusing on an
// unanswered probe would instead turn a database blip into a retirement notice
// on a deployment that may write (an owner-role deployment still writes: PRD
// v11 §5 item 5).
func RefuseWhenRevoked(w http.ResponseWriter, r *http.Request, may func(context.Context) (bool, error), logPrefix, op, orgID, tenantID string, write ErrorWriter) bool {
	ok, err := may(r.Context())
	if err != nil {
		log.Printf("[%s] %s: the legacy write privilege could not be read for tenant %s; the request proceeds and the write's own refusal is still classified: %v",
			logPrefix, op, logutil.Sanitize(tenantID), err)
		return false
	}
	if ok {
		return false
	}
	Refuse(w, r, logPrefix, op, orgID, tenantID, write)
	return true
}
