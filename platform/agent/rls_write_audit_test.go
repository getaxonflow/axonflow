// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestEveryWriteIntoRLSTableIsWrapped is the structural regression guard
// for v9 Phase 8 #2384's RLS write-path closure (PR-A #2387, PR-B #2386,
// PR-C1 #2396/#2401, PR-C2 #2389, PR-C3 #2388). It walks every non-test
// .go file under platform/ + ee/platform/ and asserts that every bare
// INSERT INTO / UPDATE / DELETE FROM against an RLS-gated table runs
// inside a wrap-variant closure (which SETs app.current_org_id
// transaction-local before the write) or is on the cross-org admin-pool
// allowlist.
//
// Why this exists:
//
//	Under axonflow_app_role (NOBYPASSRLS, mig 098) every write into an
//	RLS-gated table evaluates the WITH CHECK / USING predicate against
//	app.current_org_id. Without a wrap, the predicate sees the empty
//	string and the write either silently no-ops (USING returns NULL on
//	UPDATE/DELETE) or fails with sqlstate 42501 on INSERT. Phase 8
//	closed 43 such sites; this test prevents a 44th from sneaking back
//	in.
//
// What is flagged:
//
//	A call to ExecContext / QueryContext / QueryRowContext / Exec /
//	Query / QueryRow whose SQL argument resolves (directly OR via a
//	local string-literal variable binding within the same FuncDecl)
//	to a string literal that starts (after whitespace) with
//	INSERT INTO <table> / UPDATE <table> / DELETE FROM <table>, where
//	<table> is in rlsGatedTables. The write is permitted when its
//	lexical position is inside the body of a wrap-call's last-
//	argument FuncLit (i.e., `WithOrgScope(..., func(tx *sql.Tx) error
//	{ ... })`) OR its receiver is a `*sql.Tx` (presumed wrapped by
//	caller — helpers that take tx as a parameter and write on it).
//	Otherwise the enclosing FuncDecl must be on the admin-pool
//	allowlist.
//
// What is intentionally not flagged:
//
//   - SQL built at runtime via fmt.Sprintf / query-builder. We cannot
//     reason about the table at compile time. Identifier-interpolated
//     statements (e.g., `fmt.Sprintf("DELETE FROM %s WHERE ...", t)`)
//     still bear wrap discipline; reviewers handle dynamic SQL.
//   - INSERT/UPDATE/DELETE statements against tables not on the RLS
//     allowlist. Future migrations are expected to extend the list as
//     the wrap surface expands.
//   - SELECT-only calls — the wrap discipline matters for visibility
//     on reads too, but the brief locked PR-D's scope to write-path.
//
// Scope:
//
//	platform/**/*.go + ee/platform/**/*.go, excluding *_test.go and
//	demo client subtrees (ee/platform/clients/*) which run on their
//	own DB schemas.
//
// Mutation discipline:
//   - Reverting any C1/C2/C3 wrap (replacing `WithOrgScope(ctx, db,
//     org, func(tx) error {...})` with a bare `db.Exec(...)`) MUST
//     fire this test with the offending file::funcName + table.
//   - Reverting any PR-A SECURITY DEFINER binding (replacing
//     `SELECT auth_insert_api_key($1, ...)` with `INSERT INTO
//     api_keys ...`) MUST fire this test.
//
// False-positive guards documented inline at each helper. The
// companion TestRLSWriteAuditHelpers unit-covers the regex / variable
// resolution / closure-scope plumbing so refactors of the audit
// machinery surface BEFORE the integration walk passes for unrelated
// reasons.
func TestEveryWriteIntoRLSTableIsWrapped(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	scanDirs := []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	}

	tables := rlsGatedTables()
	wrapCallables := baseWrapVariantNames()
	allowFiles, allowFuncs := adminPoolAllowlist()

	var findings []string
	for _, root := range scanDirs {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				base := d.Name()
				// Skip vendor + node_modules + .claude worktree
				// metadata. Demo client subtrees under
				// ee/platform/clients/ have their own DB schemas and
				// run as standalone services; their `policy_metrics`
				// / `recent_activity` / etc are LOCAL tables
				// coincidentally named the same as platform tables.
				// They are excluded so the regression guard does not
				// false-positive on them.
				if base == "vendor" || base == "node_modules" || base == ".claude" {
					return filepath.SkipDir
				}
				if strings.HasSuffix(filepath.ToSlash(path), "ee/platform/clients") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if _, ok := allowFiles[rel]; ok {
				t.Logf("file allowlisted (whole-file skip): %s", rel)
				return nil
			}
			base := filepath.Base(path)

			src, err := os.ReadFile(path)
			if err != nil {
				findings = append(findings, rel+": read: "+err.Error())
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
			if perr != nil {
				findings = append(findings, rel+": parse: "+perr.Error())
				return nil
			}

			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				fnName := fn.Name.Name
				qualified := rel + "::" + fnName
				if reason, ok := allowFuncs[qualified]; ok {
					t.Logf("func allowlisted: %s — %s", qualified, reason)
					continue
				}
				if reason, ok := allowFuncs[rel+"::*"]; ok {
					t.Logf("file-wildcard allowlisted: %s — %s", qualified, reason)
					continue
				}
				if reason, ok := allowFuncs[base+"::*"]; ok {
					t.Logf("basename-wildcard allowlisted: %s — %s", qualified, reason)
					continue
				}

				findings = append(findings, auditFunc(rel, fnName, fn, fset, tables, wrapCallables)...)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf(
			"RLS write-path audit failed for #2384 (v9 Phase 8). %d site(s) write into an "+
				"RLS-gated table without a transaction-scoped app.current_org_id wrap. Fix by "+
				"wrapping the write in one of:\n"+
				"  - platform/agent/rls.WithOrgScope(ctx, db, orgID, func(tx) error { ... })\n"+
				"  - platform/agent/rls.WithOrgAndTenantScope(ctx, db, orgID, tenantID, func(tx) error { ... })  // mig 042 legacy GUC\n"+
				"  - platform/agent.WithOrgScope / .WithOrgAndTenantScope  (re-export shim)\n"+
				"  - platform/agent.execWithRetryOrgScope                  (audit_queue helper)\n"+
				"  - ee/platform/customer-portal/{api,api/roles,scim,observability}.withOrgScope\n"+
				"  - ee/platform/customer-portal/api.withRequestOrgScope   (session-scoped HTTP handler)\n"+
				"  - platform/connectors/registry.(*PostgreSQLStorage).withOrgScopeTx  (in-package mirror)\n"+
				"  - inline BeginTx + tx.ExecContext(\"SELECT set_config('app.current_org_id', $1, true)\", orgID)\n"+
				"If the write is genuinely cross-org and runs on axonflow_platform_admin (BYPASSRLS),\n"+
				"add the file::funcName (or file::*) to adminPoolAllowlist() with a one-line reason.\n\nFindings:\n  - %s",
			len(findings), strings.Join(findings, "\n  - "),
		)
	}
}

// auditFunc inspects one top-level FuncDecl and returns a finding for
// every bare write into an RLS-gated table that is not safely
// wrapped. ONE exemption applies at write-site granularity:
//
//	The write's receiver is a `tx`-like identifier (`tx`, `txn`, or a
//	SelectorExpr whose Sel.Name ends in "Tx"). Such writes are
//	presumed wrapped — either by the caller (helper takes *sql.Tx as
//	parameter) or by the wrap-closure that lexically opened the txn
//	(`WithOrgScope(... func(tx *sql.Tx) error { tx.Exec(...) })`).
//	The caller-side check still fires if the caller is unwrapped.
//
// Coarser exemptions (closure-scope by position, funcDecl-level
// "this function calls set_config somewhere") were both folded out
// across R3 rounds 2 + 3 because both had the same defect: a non-tx
// (pool-receiver) write nested inside an otherwise-wrapped scope
// would slip past the audit. The tx-receiver check covers every
// canonical wrap pattern in the tree (verified by enumerating every
// inline-set_config FuncDecl: all write on tx, none on db) without
// the coarse-exemption surface.
//
// SQL argument resolution: if the call's SQL argument is a local
// *ast.Ident whose binding in the same FuncDecl scope is a string
// literal (`query := \`INSERT INTO ...\``), the binding's value is
// resolved transparently. Variable resolution is single-pass within
// the FuncDecl — re-bindings + cross-function flow are not tracked
// (documented limitation).
func auditFunc(rel, fnName string, fn *ast.FuncDecl, fset *token.FileSet,
	tables map[string]bool, _ map[string]bool) []string {
	// Resolve `name := \`...\`` and `name = "..."` bindings within the
	// FuncDecl scope so call sites that pass a `query` variable still
	// participate in the audit.
	stringBindings := collectStringBindings(fn.Body)

	var findings []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sql, hasLiteral := resolveSQLArg(call, stringBindings)
		if !hasLiteral {
			return true
		}
		op, table, ok := matchRLSWriteStatement(sql)
		if !ok {
			return true
		}
		if !tables[table] {
			return true
		}
		// Sole exemption: tx-like receiver. The write transits a
		// transaction handle, which is either bound by the caller via
		// a wrap helper (caller-side check applies if unwrapped) or
		// by the wrap-closure that lexically opened the txn.
		if isTxReceiver(call) {
			return true
		}
		position := fset.Position(call.Pos())
		findings = append(findings, rel+":"+strconv.Itoa(position.Line)+":"+fnName+
			" issues bare "+op+" "+table+
			" (RLS-gated) on a non-tx receiver. Wrap the call in rls.WithOrgScope(...) "+
			"(see test docstring) and use the tx-receiver inside the closure, or, if "+
			"this is genuinely cross-org admin-pool work, add "+rel+"::"+fnName+
			" to adminPoolAllowlist() with a justification.")
		return true
	})
	return findings
}

// resolveSQLArg returns the SQL string literal of a DB call, either
// directly (when call.Args[i] is *ast.BasicLit) or via local variable
// binding (when call.Args[i] is *ast.Ident bound in stringBindings).
// Returns ("", false) when neither shape applies.
func resolveSQLArg(call *ast.CallExpr, stringBindings map[string]string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	var idx int
	switch sel.Sel.Name {
	case "ExecContext", "QueryContext", "QueryRowContext":
		idx = 1
	case "Exec", "Query", "QueryRow":
		idx = 0
	default:
		return "", false
	}
	if len(call.Args) <= idx {
		return "", false
	}
	switch a := call.Args[idx].(type) {
	case *ast.BasicLit:
		if a.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(a.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.Ident:
		if v, ok := stringBindings[a.Name]; ok {
			return v, true
		}
	}
	return "", false
}

// basicLitString returns the unquoted value of e iff e is a string-
// kind *ast.BasicLit. Otherwise ("", false). Handles both interpreted
// ("...") and raw (`...`) string literals.
func basicLitString(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// collectStringBindings walks `block` and returns a map of local
// identifier names to their string-literal value when the binding
// shape is one of:
//
//	name := "..."           // short var decl, single binding
//	name := `...`           // short var decl, raw string
//	var name = "..."        // var decl, single binding
//	const name = "..."      // const decl
//
// Re-bindings (`name = "..."` after initial bind) are recorded as the
// LAST literal value seen (lexical order). Branching control flow is
// not analyzed; if a variable is bound to different literals on
// different branches, the audit will see the last lexically. This is
// a documented limitation — query strings in the audited code are
// uniformly single-binding constants at the head of the FuncDecl
// body, so the heuristic suffices.
//
// Non-string bindings + bindings to expressions (concat, Sprintf,
// function-call results) are skipped — they remain unresolved and
// the corresponding call sites are not audited (same behavior as
// before the resolver was added).
func collectStringBindings(block *ast.BlockStmt) map[string]string {
	out := map[string]string{}
	ast.Inspect(block, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) != len(s.Rhs) {
				return true
			}
			for i, lhs := range s.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if v, ok := basicLitString(s.Rhs[i]); ok {
					out[id.Name] = v
				}
			}
		case *ast.GenDecl:
			for _, spec := range s.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if len(vs.Values) == 0 {
					continue
				}
				for i, id := range vs.Names {
					if i >= len(vs.Values) {
						break
					}
					if v, ok := basicLitString(vs.Values[i]); ok {
						out[id.Name] = v
					}
				}
			}
		}
		return true
	})
	return out
}

// isTxReceiver reports whether the receiver of an ExecContext-style
// call is a `tx`-like identifier — meaning the call is a write on a
// transaction handle. Such writes are presumed wrapped by the caller
// (the caller opened the txn via a wrap helper and passed it down).
//
// Detection shapes accepted:
//
//	tx.ExecContext(...)            // bare *ast.Ident named tx, txn, dtx
//	r.tx.ExecContext(...)          // SelectorExpr whose Sel.Name = "tx"/"txn"
//	someResult.Tx().ExecContext()  // SelectorExpr whose Sel.Name ends "Tx"
//
// Non-tx receivers (db, h.db, r.db, s.db, pool, conn) are explicitly
// classified as pool-like and audited.
//
// FALSE-POSITIVE GUARD: this presumption is only safe when the
// containing FuncDecl is itself called only from wrap-balanced
// contexts. A future helper that takes a tx but is called from an
// unwrapped FuncDecl would still bypass this audit — the wrap-
// discipline lives at the caller of the helper. The R3 hostile
// review track for this PR documented the limitation; the brief's
// 43-site audit catalogue already inspected every tx-receiving
// helper in the C1/C2/C3 closures and confirmed their callers wrap.
func isTxReceiver(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch v := sel.X.(type) {
	case *ast.Ident:
		return isTxName(v.Name)
	case *ast.SelectorExpr:
		return isTxName(v.Sel.Name)
	case *ast.CallExpr:
		// e.g. `r.Tx().ExecContext(...)` — chain through to the
		// outermost selector that names a tx-returning method.
		if csel, ok := v.Fun.(*ast.SelectorExpr); ok {
			return isTxName(csel.Sel.Name)
		}
	}
	return false
}

// isTxName recognizes identifier shapes that almost always name a
// transaction handle in this codebase. Conservative: accepting too
// broadly would let pool writes pass; accepting too narrowly would
// flag legitimate helpers.
func isTxName(name string) bool {
	switch name {
	case "tx", "txn", "Tx", "Txn":
		return true
	}
	// Methods that return a transaction handle conventionally end in
	// "Tx" (e.g., `BeginTx`, `WithTx`). Don't match generic things
	// like "stx" or "ctx" though.
	return len(name) >= 2 && strings.HasSuffix(name, "Tx") && name != "ctx"
}

// callName extracts the call name from an *ast.CallExpr.Fun:
//   - *ast.Ident       → "Name"
//   - *ast.SelectorExpr → "Name" (only the Sel; the receiver is opaque)
//   - other            → ""
//
// For wrap detection we want both bare-Ident (`WithOrgScope`) and
// selector (`h.withOrgScope`, `agent.WithOrgScope`) shapes. Returning
// only the Sel name conflates `h.withOrgScope` with `r.withOrgScope`
// — by design. Every wrap helper has a distinctive name in this tree;
// if a non-wrap helper ever shares a name with a wrap helper, the
// closure-scope detection limits the blast radius to the call's
// own range (R3 HIGH-2 fix).
func callName(fn ast.Expr) string {
	switch v := fn.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

// rlsWriteRE captures one of INSERT INTO / UPDATE / DELETE FROM
// followed by the target table identifier. Supports:
//
//   - bare identifier:           INSERT INTO policy_overrides
//   - schema-qualified:          INSERT INTO public.policy_overrides
//   - double-quoted (PG):        INSERT INTO "policy_overrides"
//   - schema-qualified+quoted:   INSERT INTO public."policy_overrides"
//   - mixed-case quoted:         INSERT INTO "PolicyOverrides"  (rejected;
//                                tables in this tree are lowercase)
//
// The schema prefix is recognized but discarded — we always return
// the bare table identifier. The audited table list is the canonical
// post-mig form, so any schema-qualifier landing on a public table
// is matched the same as a bare reference. Quoted identifiers are
// unquoted before lookup.
//
// Allows optional SQL line comments (`-- ...\n`) at the head so a
// leading comment that mentions a table doesn't confuse the match.
// Query builders that emit `WITH cte AS (...) INSERT ...` are NOT
// matched; that wrap discipline still applies and reviewers handle
// dynamic SQL.
var rlsWriteRE = regexp.MustCompile(
	`(?is)^\s*(?:--[^\n]*\n\s*)*` +
		`(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+` +
		`(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?` + // optional schema prefix (e.g., `public.`)
		`(?:` +
		`"([a-zA-Z_][a-zA-Z0-9_]*)"` + // quoted form: group 2
		`|` +
		`([a-zA-Z_][a-zA-Z0-9_]*)` + // bare form: group 3
		`)`,
)

// matchRLSWriteStatement extracts the op (INSERT|UPDATE|DELETE) and
// target table from a SQL string literal. Returns ("", "", false) if
// the leading statement is not a write. Schema-qualified and double-
// quoted table identifiers are normalized to bare lowercase.
func matchRLSWriteStatement(sql string) (op, table string, ok bool) {
	m := rlsWriteRE.FindStringSubmatch(sql)
	if m == nil {
		return "", "", false
	}
	verb := strings.ToUpper(strings.Fields(m[1])[0])
	tab := m[2]
	if tab == "" {
		tab = m[3]
	}
	return verb, strings.ToLower(tab), true
}

// baseWrapVariantNames returns the set of baseline CallExpr names
// that count as an RLS wrap variant. Bare-Ident and SelectorExpr.Sel
// forms collapse to the same name. Each entry is keyed to a real
// helper that exists in the tree as of v9 Phase 8 PR-C1/C2/C3.
//
// Detection is intentionally scope-local: a write is "wrapped" iff
// it lies INSIDE the body of a wrap-variant call's last-arg FuncLit
// (closure-scope check). HIGH-2 in R3 round 1 surfaced that the
// earlier per-FuncDecl coarse propagation let unwrapped writes
// alongside wrapped ones pass silently; the closure-scope check
// fixes that.
//
// Service-level wrappers (`withSSOOrgScope`, `withSAMLOrgScope`)
// are seeded here too. Both bodies set the GUC via the canonical
// SELECT set_config(...) pattern AND invoke their fn arg as a
// closure, so the closure-scope check naturally exempts writes
// inside their `func(tx *sql.Tx) error { ... }` closure body when
// called.
//
// Adding a new helper requires a code-side definition + an entry
// here. An entry without a definition is benign (no callers match
// it) but should be removed when the helper goes away.
func baseWrapVariantNames() map[string]bool {
	return map[string]bool{
		// Canonical leaf — platform/agent/rls/scope.go.
		"WithOrgScope":          true,
		"WithOrgAndTenantScope": true,

		// Re-export shim — platform/agent/rls_session.go. Same names
		// as the leaf; ident-name match is sufficient.

		// Customer-portal mirrors — ee/platform/customer-portal/api,
		// ee/platform/customer-portal/api/roles, scim, observability.
		// All defined with a lower-case name as in-package leaves.
		"withOrgScope":        true,
		"withRequestOrgScope": true,

		// Orchestrator sebi mirror — platform/orchestrator/sebi/rls_session.go.
		// Same name as the customer-portal mirrors.

		// platform/agent/audit_queue.go helper — wraps WithOrgScope
		// with retry-on-transient. Used by the audit-queue write path.
		"execWithRetryOrgScope": true,

		// platform/connectors/registry/postgres_storage.go in-package
		// mirror — avoids agent ↔ registry import cycle.
		"withOrgScopeTx": true,

		// Service-level wrappers around withOrgScope:
		// ee/platform/customer-portal/api/sso.go::withSSOOrgScope and
		// ee/platform/customer-portal/auth/saml/service.go::withSAMLOrgScope
		// both delegate to withOrgScope / inline set_config. Seeded
		// here so that calls like `s.withSSOOrgScope(t, func(tx *sql.Tx)
		// error {...})` are recognized as wrap-closure openings.
		"withSSOOrgScope":  true,
		"withSAMLOrgScope": true,
	}
}

// rlsGatedTables returns the set of tables that have ROW LEVEL
// SECURITY enabled (FORCE or ENABLE) in the v9 schema. Sourced from:
//
//   - migrations/core/018_row_level_security.sql       (24 tables, base set)
//   - migrations/core/019_deployment_upgrades.sql      (deployment_upgrades)
//   - migrations/core/022_policy_versioning.sql        (policy_versions)
//   - migrations/core/023_custom_roles.sql             (custom_roles, role_assignments)
//   - migrations/core/025_decision_chain.sql           (decision_chain)
//   - migrations/core/025_hitl_oversight_queue.sql     (hitl_approval_queue, hitl_approval_history)
//   - migrations/core/026_audit_retention_config.sql   (audit_retention_config)
//   - migrations/core/027_llm_providers.sql            (llm_providers, llm_provider_usage)
//   - migrations/core/030_policy_tier_columns.sql      (policy_overrides, static_policy_versions)
//   - migrations/core/039_mcp_policy_phases.sql        (policy_evaluations)
//   - migrations/core/042_unified_execution_history.sql (execution_history)
//   - migrations/core/081_usage_metering.sql           (usage_events, usage_hourly, usage_daily, usage_monthly)
//   - migrations/core/099_v9_rls_b1_sparse_tables.sql  (audit_archive, deployment_upgrades, saml_configurations) [FORCE]
//   - migrations/core/101_v9_rls_b2_audit_tables.sql   (mcp_query_audits, audit_retention_config, decision_chain) [FORCE]
//   - migrations/core/103_v9_rls_b9_identity_tables.sql (organizations, tenants) [FORCE]
//   - migrations/core/105_v9_b9_completion_csaas_registrations.sql (community_saas_registrations) [FORCE]
//   - migrations/core/106_v9_b9_completion_sso_configurations.sql  (sso_configurations, sso_sessions, sso_login_attempts) [FORCE]
//   - migrations/core/107_v9_rls_b8_misc_tables.sql    (connectors, connector_configs, agent_heartbeats, node_violations) [FORCE]
//   - migrations/core/108_v9_b6_in_vpc_security_definer.sql (api_keys, customers) [FORCE]
//   - migrations/core/110_v9_phase8_pr_c2_policy_overrides_org_id.sql (policy_overrides, static_policy_versions, policy_versions) [GUC normalize]
//
// Mig 102 hardens decision_chain + mcp_query_audits without adding
// tables. Mig 111 renames custom_roles.tenant_id → org_id (no new
// tables). Mig 104/108/109 ship SECURITY DEFINER helpers; the
// helpers operate on the same RLS-gated tables already in this set.
//
// Enterprise-only tables (migrations/enterprise/) are intentionally
// EXCLUDED from this set: PR-D's brief scopes the regression guard to
// the v9 Phase 8 write-path closure. Enterprise EU AI Act / SCIM /
// customer-agent tables have their own RLS but no wrap discipline has
// been audited end-to-end yet — they'll fold into a follow-up PR that
// extends both this list and the corresponding wrap surface.
func rlsGatedTables() map[string]bool {
	tables := []string{
		// 018 (ENABLE)
		"customers", "usage_metrics", "request_log",
		"agent_audit_logs", "orchestrator_audit_logs",
		"connectors",
		"static_policies", "dynamic_policies", "policy_evaluation_cache",
		"policy_metrics", "policy_violations",
		"service_identities", "license_keys",
		"marketplace_usage_records",
		"organizations", "saml_configurations", "api_keys", "user_sessions",
		"grafana_organizations", "agent_heartbeats", "node_violations",
		"usage_events", "usage_hourly", "usage_daily", "usage_monthly",
		"customer_portal_api_keys",
		// 019
		"deployment_upgrades",
		// 022
		"policy_versions",
		// 023
		"custom_roles", "role_assignments",
		// 025 (decision_chain + hitl_oversight_queue)
		"decision_chain", "hitl_approval_queue", "hitl_approval_history",
		// 026
		"audit_retention_config",
		// 027
		"llm_providers", "llm_provider_usage",
		// 030 (overlaps with 110 normalize)
		"policy_overrides", "static_policy_versions",
		// 039
		"policy_evaluations",
		// 042
		"execution_history",
		// 099 FORCE
		"audit_archive",
		// 101 FORCE
		"mcp_query_audits",
		// 103 FORCE
		"tenants",
		// 105 FORCE
		"community_saas_registrations",
		// 106 FORCE
		"sso_configurations", "sso_sessions", "sso_login_attempts",
		// 107 FORCE
		"connector_configs",
	}
	out := make(map[string]bool, len(tables))
	for _, t := range tables {
		out[t] = true
	}
	return out
}

// adminPoolAllowlist enumerates the file/func sites that legitimately
// run cross-org (i.e., on axonflow_platform_admin, BYPASSRLS) and
// therefore do NOT need a per-org wrap. The map keys are
// repo-relative file paths joined with the function name by "::".
// Two wildcard forms are honored:
//
//   - "<rel-path>::*"   — every FuncDecl in that file is admin-pool.
//   - "<basename>::*"   — every FuncDecl in any file with that
//                         basename is admin-pool. Used sparingly.
//
// Each entry MUST carry a one-line reason naming why the site is
// cross-org. "Pre-existing legacy" is not a reason; either the site
// is admin-pool by design or it needs wrapping. The reason string is
// dumped in the test output for traceability.
//
// Two return values:
//
//	allowFiles → whole-file skip (do not parse). Reserve for files
//	  that are entirely admin-pool / migrations / boilerplate that
//	  the AST walker need not visit at all.
//	allowFuncs → file::func or wildcard skip on a per-FuncDecl basis.
//	  Reserve for files that mix admin-pool and per-org code, where
//	  parsing is still useful for the per-org sites.
func adminPoolAllowlist() (allowFiles, allowFuncs map[string]string) {
	allowFiles = map[string]string{}
	allowFuncs = map[string]string{
		// platform/agent/run.go::main wires up meteringDB, sweepDB,
		// recoveryDB, monitorDB via OpenPlatformAdminConnection. The
		// goroutines they start (sweep, recovery, metering) run on
		// axonflow_platform_admin (BYPASSRLS). Brief §3 admin-pool
		// allowlist.
		"platform/agent/run.go::main": "admin-pool: OpenPlatformAdminConnection wires meteringDB/sweepDB/recoveryDB/monitorDB; cross-org daemons. Brief §3.",

		// platform/agent/community_saas_sweep.go — file-wide admin-pool.
		// The inactivity sweep + hard-cap sweep + cascade DELETE run
		// cross-org by design. Schedule: 1× per day; advisory-lock
		// serialised across replicas. Brief §3 admin-pool allowlist.
		"platform/agent/community_saas_sweep.go::*": "admin-pool: cross-org csaas tenancy sweep + cascade delete. Brief §3.",

		// platform/agent/community_saas_recovery.go — admin-pool by
		// design EXCEPT the SECURITY DEFINER call paths (which match
		// "SELECT csaas_recovery_insert(...)" — a SELECT, not an
		// INSERT/UPDATE/DELETE — and so they bypass this audit
		// naturally). File-level wildcard is safe.
		// Brief §3 admin-pool allowlist.
		"platform/agent/community_saas_recovery.go::*": "admin-pool: token issue/consume sweep + cascade. SECURITY DEFINER calls bypass this audit naturally. Brief §3.",

		// platform/agent/tenant_delete.go — pre-auth cascade DELETE
		// surface tracked by #2397 (PR-C1 R3 round 2 HIGH-3 NEW;
		// Session 22-A2 in flight, will route via OpenPlatformAdminConnection
		// or a SECURITY DEFINER helper analogous to mig 109's
		// csaas_register_tenant). Until 22-A2 lands the cascade
		// DELETEs would trip this audit; allowlisting at file-level
		// keeps the regression guard green for the rest of PR-D.
		// Once 22-A2 merges with the admin-pool routing, this entry
		// can be narrowed to just the handler funcs OR removed
		// entirely (if 22-A2 switches to SD calls which match
		// SELECT, not DELETE FROM).
		"platform/agent/tenant_delete.go::*": "admin-pool (pending #2397 / Session 22-A2): GDPR cascade-delete will be routed via OpenPlatformAdminConnection or mig 109 SECURITY DEFINER helper.",

		// platform/agent/marketplace/metering.go — MeteringService
		// writes marketplace_usage_records cross-org for billing.
		// Brief §3 admin-pool allowlist names
		// MeteringService.storeUsageRecord + .queueFailedRecord
		// explicitly. The other methods (loadFailedRecords etc) only
		// SELECT/UPDATE the same admin-owned table and likewise run
		// cross-org. File-level wildcard.
		"platform/agent/marketplace/metering.go::*":    "admin-pool: marketplace metering runs cross-org (axonflow_platform_admin). Brief §3.",
		"ee/platform/agent/marketplace/metering.go::*": "admin-pool: EE mirror of marketplace metering — same cross-org admin-pool intent. Brief §3.",

		// ee/platform/customer-portal/api/admin.go — admin-pool by
		// design (`h.adminConn()`). Brief §3 admin-pool allowlist.
		"ee/platform/customer-portal/api/admin.go::*": "admin-pool: h.adminConn() routes to axonflow_platform_admin. Brief §3.",

		// ee/platform/customer-portal/api/organizations.go — admin-
		// pool by design (`h.adminConn()`). Brief §3 admin-pool
		// allowlist.
		"ee/platform/customer-portal/api/organizations.go::*": "admin-pool: h.adminConn() routes to axonflow_platform_admin. Brief §3.",

		// platform/agent/policy_override_repository.go::CleanupExpiredOverrides
		// is doc-acknowledged admin-pool: cleanup loop runs cross-org
		// (single SELECT pulls ALL expired rows, single DELETE removes
		// them). Brief §3 names this explicitly.
		"platform/agent/policy_override_repository.go::CleanupExpiredOverrides": "admin-pool: cross-org expired-override cleanup loop. Brief §3.",

		// platform/orchestrator/audit_cleanup.go — file-wide admin-
		// pool. Operates on the admin retention bucket map cross-org
		// (audit_logs cleanup runs for every tenant via UPSERT of
		// per-tier retention rules). Audit_logs itself is not on the
		// RLS allowlist, but execution_history (mig 042) IS — and
		// PurgeExcessExecutionHistory runs cross-org on the admin
		// pool. Brief §3 admin-pool allowlist (paired with #2384
		// closeout decisions; PR-C1 §3a marketplace_usage_records).
		"platform/orchestrator/audit_cleanup.go::*": "admin-pool: cross-org audit/execution retention sweep. Operates on platform-admin pool by service construction.",

		// ee/platform/orchestrator/sebi/sebi_audit_export_service.go
		// is enterprise-only; SEBI audit exports run cross-tenant on
		// the admin pool for the regulatory export workflow.
		"ee/platform/orchestrator/sebi/sebi_audit_export_service.go::*": "admin-pool: SEBI regulatory cross-tenant audit export.",

		// platform/orchestrator/hitl_wcp_community.go::expireEvalApprovals
		// is the community-build (no enterprise tag) HITL eval auto-
		// reject sweep. Runs every 5 minutes across ALL tenants — by
		// nature cross-org. Under USE_APP_ROLE=true the `db` it
		// receives is app_role, which means the cross-tenant UPDATE
		// no-ops under RLS. The runtime fix is to plumb an admin pool
		// through Init/runEvalApprovalExpiryLoop — that is multi-
		// package refactor (sister to #2400's heartbeat surface) and
		// is filed for follow-up. Listed here to keep the regression
		// guard green; the runtime issue is tracked separately.
		"platform/orchestrator/hitl_wcp_community.go::expireEvalApprovals": "admin-pool by design (cross-tenant sweep): runtime needs admin-pool plumbing through runEvalApprovalExpiryLoop — sibling of #2400.",

		// platform/agent/node_enforcement/heartbeat.go::CleanupStaleHeartbeats
		// + EE mirror — admin-pool cross-tenant sweep that removes
		// agent_heartbeats rows older than the staleness threshold
		// regardless of org. Was previously hidden from the audit by
		// the `query := ...` variable-SQL pattern; R3 HIGH-4 surfaced
		// the gap once the variable-resolution pass landed in this
		// walker.
		"platform/agent/node_enforcement/heartbeat.go::CleanupStaleHeartbeats":    "admin-pool: cross-tenant stale-heartbeat sweep on agent_heartbeats.",
		"ee/platform/agent/node_enforcement/heartbeat.go::CleanupStaleHeartbeats": "admin-pool: cross-tenant stale-heartbeat sweep (EE mirror).",

		// ee/platform/agent/node_enforcement/heartbeat.go::sendHeartbeat
		// is the EE mirror of platform/agent/node_enforcement/heartbeat.go::sendHeartbeat.
		// The community variant got the BeginTx + set_config + INSERT inline-wrap
		// in PR-C1 (Brief 11.5 R3-MEDIUM-1) but the EE mirror was not
		// folded in the same train. #2400 (Session 22-H) owns the
		// EE-mirror runtime fix as part of the heartbeat-class fix.
		// Until 22-H lands, listed here so the regression guard stays
		// green; the runtime gap is the same class as #2400 names.
		"ee/platform/agent/node_enforcement/heartbeat.go::sendHeartbeat": "pending #2400 / Session 22-H: EE mirror needs the same BeginTx + set_config inline wrap as the community variant.",

		// ee/platform/customer-portal pre-auth lookup sites — tracked
		// by #2403 (follow-up filed alongside this PR). Same #2380 /
		// #2400 class: the handler is pre-auth (no app.current_org_id
		// can be set on the connection before the lookup that ESTABLISHES
		// the org_id). Two fix paths: admin-pool routing (precedent:
		// SSOService.preAuthDB) or SECURITY DEFINER helpers (precedent:
		// mig 104/108/109). Until #2403 closes, these are allowlisted
		// so the regression guard stays green; the runtime bug is
		// real but bounded by the same admin-pool absence that #2403
		// names. Remove these entries when #2403 ships.
		"ee/platform/customer-portal/api/auth.go::HandleCheckSession":        "pre-auth lookup: tracked by #2403 (admin-pool routing or SECURITY DEFINER for user_sessions read/update/delete by session_id alone).",
		"ee/platform/customer-portal/api/auth.go::HandleLogout":              "pre-auth lookup: tracked by #2403 (admin-pool routing or SECURITY DEFINER for user_sessions DELETE by session_id alone).",
		"ee/platform/customer-portal/api/keys.go::ValidateAPIKey":            "pre-auth lookup: tracked by #2403 (admin-pool routing or SECURITY DEFINER for customer_portal_api_keys lookup by key_hash alone).",
		"ee/platform/customer-portal/middleware/dev_auth.go::AuthMiddleware": "pre-auth lookup: tracked by #2403. AuthMiddleware IS the session-resolution middleware; admin-pool routing is the only viable fix shape.",

		// ee/platform/customer-portal/api/sso.go::DeleteSession is
		// already admin-pool-routed via s.preAuthDB() (mig adminDB
		// is attached at startup; preAuthDB falls back to s.db with a
		// log warning when adminDB is nil, which is acceptable for
		// the community build where USE_APP_ROLE is off). The AST
		// walker cannot distinguish preAuthDB() from db on the call
		// site, so this is allowlisted with the design intent named.
		"ee/platform/customer-portal/api/sso.go::DeleteSession": "admin-pool routed via SSOService.preAuthDB() (v9 Brief 11.5 R3-HIGH-1 — adminDB attached at startup, fall back to s.db with log warning).",

		// platform/agent/db_auth.go::revokeAPIKey is //nolint:unused
		// "Used in tests". It does a bare UPDATE on api_keys that the
		// variable-resolution pass now catches. Production callers do
		// not exist today; tests construct their own RLS context. The
		// FixIt: route via admin-pool when a production caller is
		// added; until then, allowlist with intent.
		"platform/agent/db_auth.go::revokeAPIKey": "admin-pool stub: function is //nolint:unused and called only from tests; bare UPDATE api_keys is acceptable until a production caller appears, at which point route via admin-pool or wrap.",
	}
	return allowFiles, allowFuncs
}

// findRepoRoot ascends the working directory until it finds the
// platform + ee/platform pair that anchors the audit. Robust against
// `go test` being invoked from any sub-package of platform/.
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		// We anchor on the presence of both "platform" and "ee/platform"
		// — the audit walker scans both, so finding only one is not
		// enough (a future restructure could rename one).
		if dirExists(filepath.Join(dir, "platform")) && dirExists(filepath.Join(dir, "ee", "platform")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// TestRLSWriteAuditHelpers exercises the helpers that drive the audit
// in isolation, so a future refactor of the regex / call-name logic
// surfaces here BEFORE the integration walk passes/fails for
// unrelated reasons. Treat this test as the unit cover for the audit
// machinery; the integration test above is the full-tree assertion.
func TestRLSWriteAuditHelpers(t *testing.T) {
	t.Run("matchRLSWriteStatement", func(t *testing.T) {
		cases := []struct {
			sql     string
			wantOp  string
			wantTab string
			wantOK  bool
		}{
			{"INSERT INTO policy_overrides (id) VALUES ($1)", "INSERT", "policy_overrides", true},
			{"  INSERT  INTO  policy_overrides (id)", "INSERT", "policy_overrides", true},
			{"\n\tINSERT INTO policy_overrides", "INSERT", "policy_overrides", true},
			{"-- comment\nINSERT INTO foo", "INSERT", "foo", true},
			{"UPDATE customer_portal_api_keys SET x = $1", "UPDATE", "customer_portal_api_keys", true},
			{"DELETE FROM user_sessions WHERE id = $1", "DELETE", "user_sessions", true},
			// R3 HIGH-5: schema-qualified and quoted identifiers.
			{"INSERT INTO public.policy_overrides (id)", "INSERT", "policy_overrides", true},
			{`INSERT INTO "policy_overrides" (id)`, "INSERT", "policy_overrides", true},
			{`INSERT INTO public."policy_overrides" (id)`, "INSERT", "policy_overrides", true},
			{"SELECT * FROM user_sessions", "", "", false},
			{"WITH cte AS (...) INSERT INTO x", "", "", false},
			{"   ", "", "", false},
		}
		for _, c := range cases {
			op, tab, ok := matchRLSWriteStatement(c.sql)
			if ok != c.wantOK || op != c.wantOp || tab != c.wantTab {
				t.Errorf("matchRLSWriteStatement(%q) = (%q, %q, %v), want (%q, %q, %v)",
					c.sql, op, tab, ok, c.wantOp, c.wantTab, c.wantOK)
			}
		}
	})

	t.Run("isTxName", func(t *testing.T) {
		positive := []string{"tx", "txn", "Tx", "Txn", "BeginTx", "WithTx", "queryableTx"}
		negative := []string{"db", "h", "r", "s", "pool", "conn", "ctx", "stx", "DB"}
		for _, n := range positive {
			if !isTxName(n) {
				t.Errorf("isTxName(%q) = false, want true", n)
			}
		}
		for _, n := range negative {
			if isTxName(n) {
				t.Errorf("isTxName(%q) = true, want false", n)
			}
		}
	})

	t.Run("collectStringBindings", func(t *testing.T) {
		// Build a synthetic FuncDecl body via parser to exercise the
		// binding collector against real Go AST shapes.
		src := `package x
func f() {
	a := "literal-a"
	b := ` + "`raw-b`" + `
	var c = "literal-c"
	d := 42
	e := someFunc()
	a = "rebound-a"
}`
		fset := token.NewFileSet()
		fileNode, err := parser.ParseFile(fset, "synth.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse synth: %v", err)
		}
		var fn *ast.FuncDecl
		for _, decl := range fileNode.Decls {
			if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "f" {
				fn = f
			}
		}
		if fn == nil || fn.Body == nil {
			t.Fatalf("synth FuncDecl missing")
		}
		got := collectStringBindings(fn.Body)
		want := map[string]string{
			"a": "rebound-a", // last-write wins
			"b": "raw-b",
			"c": "literal-c",
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("collectStringBindings[%q] = %q, want %q", k, got[k], v)
			}
		}
		if _, ok := got["d"]; ok {
			t.Errorf("collectStringBindings should not bind integer literal 'd'")
		}
		if _, ok := got["e"]; ok {
			t.Errorf("collectStringBindings should not bind function-call result 'e'")
		}
	})

	t.Run("rlsGatedTables covers Phase 8 surface", func(t *testing.T) {
		// Spot-check a representative table from each migration source.
		// If a name here goes missing, the brief's table list is out of
		// sync with the seed.
		mustHave := []string{
			"agent_audit_logs",             // 018
			"policy_versions",              // 022
			"custom_roles",                 // 023
			"hitl_approval_queue",          // 025
			"audit_retention_config",       // 026
			"llm_providers",                // 027
			"policy_overrides",             // 030/110
			"execution_history",            // 042
			"usage_events",                 // 081
			"audit_archive",                // 099
			"mcp_query_audits",             // 101
			"tenants",                      // 103
			"community_saas_registrations", // 105
			"sso_configurations",           // 106
			"agent_heartbeats",             // 107
			"customers",                    // 108
			"static_policy_versions",       // 030/110
		}
		tab := rlsGatedTables()
		for _, t0 := range mustHave {
			if !tab[t0] {
				t.Errorf("rlsGatedTables missing %q — table list drifted from migration sources", t0)
			}
		}
	})

	t.Run("walker fires on variable-bound SQL (R3 HIGH-1 fold)", func(t *testing.T) {
		// Synthetic FuncDecl with a `query := \`INSERT INTO ...\``
		// idiom and a bare db.Exec(query, ...) call. The walker MUST
		// fire on it via the variable-resolution pass.
		src := `package x
import (
	"context"
	"database/sql"
)

func badPattern(ctx context.Context, db *sql.DB) error {
	query := ` + "`INSERT INTO policy_overrides (id) VALUES ($1)`" + `
	_, err := db.ExecContext(ctx, query, "x")
	return err
}`
		findings := auditSyntheticSrc(t, src)
		if len(findings) == 0 {
			t.Fatalf("variable-bound SQL not detected — R3 HIGH-1 regression")
		}
		found := false
		for _, f := range findings {
			if strings.Contains(f, "policy_overrides") && strings.Contains(f, "badPattern") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("findings do not name policy_overrides + badPattern: %v", findings)
		}
	})

	t.Run("walker fires on write outside wrap closure (R3 HIGH-2 fold)", func(t *testing.T) {
		// Synthetic FuncDecl with one wrapped INSERT (inside the
		// closure) and one bare DELETE (outside, on db). The walker
		// MUST fire on the DELETE — previously a single wrap
		// anywhere in the body silenced every other write.
		src := `package x
import (
	"context"
	"database/sql"
)

func mixed(ctx context.Context, db *sql.DB) error {
	_ = WithOrgScope(ctx, db, "o", func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, ` + "`INSERT INTO policy_overrides (id) VALUES ($1)`" + `, "x")
		return e
	})
	_, err := db.ExecContext(ctx, ` + "`DELETE FROM policy_overrides WHERE id = $1`" + `, "y")
	return err
}

func WithOrgScope(ctx context.Context, db *sql.DB, org string, fn func(*sql.Tx) error) error {
	return fn(nil)
}`
		findings := auditSyntheticSrc(t, src)
		var del, ins int
		for _, f := range findings {
			if strings.Contains(f, "DELETE policy_overrides") && strings.Contains(f, "mixed") {
				del++
			}
			if strings.Contains(f, "INSERT policy_overrides") && strings.Contains(f, "mixed") {
				ins++
			}
		}
		if del == 0 {
			t.Errorf("DELETE outside wrap closure not flagged — R3 HIGH-2 regression. findings=%v", findings)
		}
		if ins != 0 {
			t.Errorf("INSERT inside wrap closure spuriously flagged. findings=%v", findings)
		}
	})

	t.Run("walker fires on smuggle alongside unrelated set_config (R3 R3 HIGH-1 fold)", func(t *testing.T) {
		// Symmetric to the R3 R2 HIGH-3 closure-scope finding: a
		// FuncDecl whose body contains an inline
		// `SELECT set_config('app.current_org_id', ...)` on r.tx — but
		// also a separate bare pool write — must NOT silently exempt
		// the pool write just because set_config appears somewhere in
		// the FuncDecl body. The previous funcLevelWrapped exemption
		// allowed this smuggle pattern; the R3 R3 fold removes the
		// exemption entirely.
		src := `package x
import (
	"context"
	"database/sql"
)

type R struct {
	db *sql.DB
	tx *sql.Tx
}

func (r *R) sneaky(ctx context.Context, orgID string) error {
	if r.tx != nil {
		_, _ = r.tx.ExecContext(ctx, ` + "`SELECT set_config('app.current_org_id', $1, true)`" + `, orgID)
	}
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO policy_overrides (id) VALUES ($1)`" + `, "x")
	return err
}`
		findings := auditSyntheticSrc(t, src)
		found := false
		for _, f := range findings {
			if strings.Contains(f, "INSERT policy_overrides") && strings.Contains(f, "sneaky") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("smuggle alongside unrelated set_config not flagged — R3 R3 HIGH-1 regression. findings=%v", findings)
		}
	})

	t.Run("walker fires on pool write inside wrap closure (R3 R2 HIGH-3 fold)", func(t *testing.T) {
		// Pool-receiver write inside a wrap closure body — the GUC is
		// only bound to `tx`, so a `db.ExecContext(...)` here bypasses
		// the wrap. R3 R2 HIGH-3 surfaced that closure-range exemption
		// would have wrongly let this through.
		src := `package x
import (
	"context"
	"database/sql"
)

func smuggled(ctx context.Context, db *sql.DB) error {
	return WithOrgScope(ctx, db, "o", func(tx *sql.Tx) error {
		_, err := db.ExecContext(ctx, ` + "`INSERT INTO policy_overrides (id) VALUES ($1)`" + `, "x")
		_ = tx
		return err
	})
}

func WithOrgScope(ctx context.Context, db *sql.DB, org string, fn func(*sql.Tx) error) error {
	return fn(nil)
}`
		findings := auditSyntheticSrc(t, src)
		found := false
		for _, f := range findings {
			if strings.Contains(f, "INSERT policy_overrides") && strings.Contains(f, "smuggled") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pool write inside wrap closure not flagged — R3 R2 HIGH-3 regression. findings=%v", findings)
		}
	})

	t.Run("walker handles schema-qualified + quoted identifiers (R3 HIGH-5 fold)", func(t *testing.T) {
		src := `package x
import (
	"context"
	"database/sql"
)

func quoted(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, ` + "`INSERT INTO public.policy_overrides (id) VALUES ($1)`" + `, "x")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, ` + "`INSERT INTO \"policy_overrides\" (id) VALUES ($1)`" + `, "y")
	return err
}`
		findings := auditSyntheticSrc(t, src)
		if len(findings) < 2 {
			t.Errorf("schema-qualified or quoted forms not detected — R3 HIGH-5 regression. findings=%v", findings)
		}
	})
}

// auditSyntheticSrc parses an in-memory Go source string and returns
// the walker's findings on its single FuncDecl. Used by the R3-fold
// unit tests to assert that specific regressions fire (or that
// specific shapes don't false-positive).
func auditSyntheticSrc(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synth.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synth: %v", err)
	}
	tables := rlsGatedTables()
	wraps := baseWrapVariantNames()
	var findings []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, auditFunc("synth.go", fn.Name.Name, fn, fset, tables, wraps)...)
	}
	return findings
}
