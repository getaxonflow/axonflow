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

// TestEveryReadFromRLSTableIsScoped is the READ-side sibling of
// TestEveryWriteIntoRLSTableIsWrapped — the structural regression guard for
// #3039/#3048's RLS-blind READ class. It walks every non-test .go file under
// platform/ + ee/platform/ and asserts that every bare SELECT touching an
// RLS-gated table runs inside a wrap-variant closure (SET LOCAL
// app.current_org_id before the read), on a transaction handle, or is on the
// read allowlist (deliberate cross-org admin-pool readers, pre-auth discovery
// readers with documented post-authorization, or legacy owner-pool-only
// paths).
//
// Why this exists:
//
//	Writers wrapped ≠ readers wrapped. Under axonflow_app_role a bare read
//	of an RLS-gated table fails to SILENT ZERO ROWS — no error, no log.
//	#3039 lived in the orchestrator's dynamic-policy readers for ~5 weeks
//	on prod (tenant policy gates evaluated NOTHING); #3048 was the same
//	class in the agent's static_policies readers (check-input/check-output
//	evaluated 0 policies — content enforcement silently OFF). The write
//	audit deliberately scoped SELECTs out; this test closes that gap.
//
// What is flagged:
//
//	A Query/QueryRow/QueryContext/QueryRowContext call whose SQL argument
//	resolves (directly or via a local string-literal binding) to a string
//	that references an RLS-gated table via FROM or JOIN, where the
//	receiver is not a tx-like handle and the enclosing FuncDecl is not on
//	the allowlist. `DELETE FROM <table>` heads are the write audit's
//	territory and are stripped before matching; a sub-SELECT inside a
//	write statement still counts as a read.
//
// What is intentionally not flagged (same limitations as the write audit):
//
//   - SQL built at runtime (fmt.Sprintf/query builders) where the table
//     name cannot be resolved to a literal in the same FuncDecl. Sprintf
//     FORMAT strings that name an RLS table verbatim ARE matched (the
//     resolver treats the format literal as the SQL) — the #3048 List
//     readers were exactly this shape.
//   - SELECT set_config(...) / SECURITY DEFINER helper calls — no FROM.
//
// Allowlist discipline: every entry MUST carry a one-line justification
// naming why the bare read is safe (admin-pool by construction, post-
// authorized discovery read, pre-org bootstrap, or owner-pool-only legacy
// path). "Pre-existing" is not a justification.
func TestEveryReadFromRLSTableIsScoped(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	scanDirs := []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	}
	presentDirs := scanDirs[:0]
	for _, d := range scanDirs {
		if _, err := os.Stat(d); err == nil {
			presentDirs = append(presentDirs, d)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", d, err)
		} else {
			t.Logf("scan dir %s not present in this checkout (likely community sync); skipping", d)
		}
	}
	scanDirs = presentDirs

	tables := rlsGatedReadTables()
	allowFiles, allowFuncs := rlsReadAllowlist()

	var findings []string
	for _, root := range scanDirs {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				base := d.Name()
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
			if reason, ok := allowFiles[rel]; ok {
				t.Logf("file allowlisted (whole-file skip): %s — %s", rel, reason)
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

				findings = append(findings, auditReadFunc(rel, fnName, fn, fset, tables)...)
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
			"RLS read-path audit failed (#3039/#3048). %d site(s) read an RLS-gated table "+
				"without a transaction-scoped app.current_org_id wrap — under axonflow_app_role "+
				"these reads return SILENT ZERO ROWS. Fix by wrapping the read in "+
				"rls.WithOrgScope / rls.WithOrgAndTenantScope (two disjoint scoped passes when the "+
				"result must include 'global'-scope system rows — see StaticPolicyRepository.List), "+
				"routing a post-authorized discovery read through the BYPASSRLS admin pool, or, if the "+
				"bare read is genuinely safe, adding the file::funcName to rlsReadAllowlist() with a "+
				"one-line justification.\n\nFindings:\n  - %s",
			len(findings), strings.Join(findings, "\n  - "),
		)
	}
}

// auditReadFunc inspects one top-level FuncDecl and returns a finding for
// every bare read touching an RLS-gated table that is not on a tx-like
// receiver. Mirrors auditFunc (write audit) — see its docstring for the
// variable-resolution and tx-receiver semantics and their documented
// limitations.
func auditReadFunc(rel, fnName string, fn *ast.FuncDecl, fset *token.FileSet, tables map[string]bool) []string {
	stringBindings := collectStringBindings(fn.Body)

	var findings []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sql, hasLiteral := resolveReadSQLArg(call, stringBindings)
		if !hasLiteral {
			return true
		}
		matched := matchRLSReadTables(sql, tables)
		if len(matched) == 0 {
			return true
		}
		if isTxReceiver(call) {
			return true
		}
		position := fset.Position(call.Pos())
		findings = append(findings, rel+":"+strconv.Itoa(position.Line)+":"+fnName+
			" issues bare read of "+strings.Join(matched, ",")+
			" (RLS-gated) on a non-tx receiver — silent zero rows under axonflow_app_role. "+
			"Wrap in rls.WithOrgScope(...) (tx receiver inside the closure), route through the "+
			"BYPASSRLS admin pool with post-authorization, or add "+rel+"::"+fnName+
			" to rlsReadAllowlist() with a justification.")
		return true
	})
	return findings
}

// resolveReadSQLArg mirrors resolveSQLArg but also treats fmt.Sprintf
// FORMAT literals as the SQL under audit: the #3048 List/GetEffective
// readers built their statements via fmt.Sprintf with the table name in
// the format literal, which the write-audit resolver could not see.
// Both the direct-call shape (Sprintf inline as the SQL arg) and the
// bound-variable shape (query := fmt.Sprintf(`...`, x)) are handled;
// collectStringBindings already skips Sprintf results, so the binding
// resolution here inspects the call's own argument expression.
func resolveReadSQLArg(call *ast.CallExpr, stringBindings map[string]string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	var idx int
	switch sel.Sel.Name {
	case "QueryContext", "QueryRowContext":
		idx = 1
	case "Query", "QueryRow":
		idx = 0
	default:
		return "", false
	}
	if len(call.Args) <= idx {
		return "", false
	}
	return resolveStringExpr(call.Args[idx], stringBindings)
}

// resolveStringExpr resolves an expression to a string literal: directly,
// via a local binding, or via a fmt.Sprintf whose FORMAT argument resolves.
func resolveStringExpr(e ast.Expr, stringBindings map[string]string) (string, bool) {
	switch a := e.(type) {
	case *ast.BasicLit:
		if s, ok := basicLitString(a); ok {
			return s, true
		}
	case *ast.Ident:
		if v, ok := stringBindings[a.Name]; ok {
			return v, true
		}
	case *ast.CallExpr:
		if csel, ok := a.Fun.(*ast.SelectorExpr); ok && csel.Sel.Name == "Sprintf" && len(a.Args) > 0 {
			return resolveStringExpr(a.Args[0], stringBindings)
		}
	}
	return "", false
}

// deleteFromHeadRE strips a leading DELETE FROM <table> — that is the write
// audit's territory; a sub-SELECT later in the same statement still counts.
var deleteFromHeadRE = regexp.MustCompile(`(?is)^\s*(?:--[^\n]*\n\s*)*DELETE\s+FROM\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?"?[a-zA-Z_][a-zA-Z0-9_]*"?`)

// rlsReadRefRE captures every FROM/JOIN <identifier> reference in a SQL
// string (schema-qualified and quoted forms normalized). EXTRACT(x FROM col)
// and SUBSTRING(x FROM n) also match — their following identifier is a
// column/placeholder, which the RLS table-name lookup filters out.
var rlsReadRefRE = regexp.MustCompile(
	`(?is)\b(?:FROM|JOIN)\s+` +
		`(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?` +
		`(?:"([a-zA-Z_][a-zA-Z0-9_]*)"|([a-zA-Z_][a-zA-Z0-9_]*))`,
)

// matchRLSReadTables returns the distinct RLS-gated tables a SQL string
// reads (via FROM/JOIN), in first-appearance order.
func matchRLSReadTables(sql string, tables map[string]bool) []string {
	sql = deleteFromHeadRE.ReplaceAllString(sql, "")
	var out []string
	seen := map[string]bool{}
	for _, m := range rlsReadRefRE.FindAllStringSubmatch(sql, -1) {
		tab := m[1]
		if tab == "" {
			tab = m[2]
		}
		tab = strings.ToLower(tab)
		if tables[tab] && !seen[tab] {
			seen[tab] = true
			out = append(out, tab)
		}
	}
	return out
}

// rlsGatedReadTables is the read-audit table set: the write audit's set plus
// detection_action_overrides (mig 120 — RLS-enabled after the write audit's
// list was frozen).
func rlsGatedReadTables() map[string]bool {
	tables := rlsGatedTables()
	tables["detection_action_overrides"] = true
	return tables
}

// rlsReadAllowlist enumerates file/func sites whose bare reads of RLS-gated
// tables are deliberate. Keys and wildcard forms match adminPoolAllowlist
// (see the write audit). Populated by the #3048 full-repo read census — every
// entry names WHY the bare read is safe.
func rlsReadAllowlist() (allowFiles, allowFuncs map[string]string) {
	allowFiles = map[string]string{}
	allowFuncs = map[string]string{
		// ── Dual-shape readers: the flagged line is the BARE branch of a
		// function whose scoped branch sits alongside it (#3048). The bare
		// branch runs only when the caller org is genuinely unknown —
		// single-tenant/community contexts on owner pools (RLS bypassed).
		// platform/orchestrator/hitl_wcp_community.go::expireEvalApprovals — the
		// BACKLOG COUNT the sweeper logs on a full batch (#3520). It reads
		// hitl_approval_queue with no org scope, deliberately: it is a
		// CROSS-TENANT count, the same population the sweep it annotates has
		// just operated on, and scoping it per-org would report a number that
		// does not describe the thing the operator is being warned about.
		//
		// THE JUSTIFICATION IS STRUCTURAL, NOT A PROMISE. This function now
		// REFUSES TO RUN without a cross-tenant BYPASSRLS pool: InitializeWCPHITL
		// does not start the sweeper at all when one is unavailable
		// (hitl_expiry_pool.go), and ExpireDueReturning rejects a nil pool. So
		// the receiver here cannot be an RLS-scoped pool on any path that
		// reaches this line - which is exactly what the analyser cannot see, and
		// exactly what the pre-#3520 code could NOT have claimed.
		"platform/orchestrator/hitl_wcp_community.go::expireEvalApprovals": "admin-pool by construction: cross-tenant backlog COUNT beside the cross-tenant sweep; the sweeper refuses to start without a BYPASSRLS pool (#3520).",

		"platform/agent/mcp_richer_context.go::lookupPolicyMeta":         "dual-shape reader: scoped two-pass (org → 'global') when scopeOrg set; bare branch = owner-pool legacy contexts only (#3048).",
		"platform/agent/mcp_richer_context.go::lookupPolicyVersionsByID": "dual-shape reader: scoped org+'global' merge when caller org known; bare branch = owner-pool legacy contexts only (#3048).",
		"platform/agent/mcp_richer_context.go::lookupActiveOverride":     "dual-shape reader: scoped resolve+override when scopeOrg set; the flagged single-statement is the owner-pool legacy branch (#3048).",
		"platform/agent/static_policy_repository.go::GetByID":            "dual-shape reader: caller-org scope + 'global' fallback when OrgIDFromContext set; bare branch = owner-pool legacy + post-authorized by callerOrgOwnsStaticPolicy (#3048).",
		"platform/agent/policy_override_repository.go::GetByID":          "dual-shape reader: caller-org scope when OrgIDFromContext set; bare branch = owner-pool legacy contexts (#3048).",
		"platform/agent/decision_chain.go::GetChain":                     "dual-shape reader: caller-org scope when OrgIDFromContext set; bare branch = owner-pool legacy contexts; org-scoped fetchers in decision_chain_signing.go are the audited surface (#3048).",
		"platform/shared/policy/loader.go::GetPolicyByID":                "dual-shape discovery reader: bare pass for owner pools + 'global'-scoped retry for system rows; no production callers today (#3048).",
		"platform/agent/static_policy_repository.go::scopedListBare":     "deliberate legacy bare read: filterless (tenantID==\"\") cross-tenant ops listing on owner pools; cross-org work belongs on the admin role (#3048).",

		// ── RBI cross-org worker sweeps (#3103). Every other read in the RBI
		// package is now wrapped; these two have NO caller org — the statement
		// spans every tenant by design and rls.WithOrgScope rejects an empty
		// orgID precisely so "scope me to nothing" cannot be spelled by
		// accident. They must run on the BYPASSRLS axonflow_platform_admin
		// pool. Neither has a production caller today
		// (ProcessPendingExports/CleanupExpiredExports are unwired), so no live
		// path reads zero rows; wiring either one MUST construct the repository
		// with the admin pool. Documented in full on the methods themselves.
		"platform/orchestrator/rbi/auditexport_repository.go::GetPending": "cross-org worker sweep (status='pending', no org predicate by design) — admin-pool only; unwired today (#3103).",
		"platform/orchestrator/rbi/auditexport_repository.go::GetExpired": "cross-org retention sweep (expires_at < NOW(), no org predicate by design) — admin-pool only; unwired today (#3103).",

		// ── BYPASSRLS lookup/refresh pools by construction: the receiver is
		// an accessor that resolves to the platform-admin pool when wired
		// (SetCrossOrgDB / refreshDB / crossOrgDB — #3039/#3048 pattern);
		// the AST walker cannot see through the accessor.
		"platform/shared/execution/repository.go::Get":                     "BYPASSRLS lookup pool via r.lookup() — #3039 discovery reads, callers post-authorize.",
		"platform/shared/execution/repository.go::getByMetadataHardcoded":  "BYPASSRLS lookup pool via r.lookup() — #3039 discovery reads, callers post-authorize.",
		"platform/orchestrator/policy_api_repository.go::CountOrgPolicies": "BYPASSRLS pool via r.crossOrg() — #3039 deliberate cross-tenant count.",
		// #3319: the bare reads that used to live directly in refreshPolicies /
		// seedDefaultData moved into the shared loader (sharedpolicy.
		// RefreshDynamicPolicies / CountAllDynamicPolicies below); these two
		// call sites now only select the pool (e.crossOrgDB()) and pass it in,
		// so the walker no longer sees a Query call to flag here — the
		// allowlist entry lives at the loader functions instead.
		"platform/shared/policy/loader.go::CountAllDynamicPolicies":                "BYPASSRLS-by-caller-contract, not by construction: takes db *sql.DB directly, so the walker can't see through the accessor. Sole caller is DatabaseDynamicPolicyEngine.seedDefaultData (platform/orchestrator/db_dynamic_policies.go), which passes e.crossOrgDB() — verified by grep, no other caller exists. #3319 moved this cross-org boot COUNT out of the engine into the shared loader; #3039.",
		"platform/shared/policy/loader.go::RefreshDynamicPolicies":                 "Same BYPASSRLS-by-caller-contract shape as CountAllDynamicPolicies above, same sole caller: DatabaseDynamicPolicyEngine.refreshPolicies (platform/orchestrator/db_dynamic_policies.go) passes e.crossOrgDB() at both call sites (segment and segment-less retry) — verified by grep, no other caller exists. Not flagged by the walker today (the SQL is reached through a package-level query-string identifier the binding resolver doesn't follow, not a local literal), but carries the identical exposure, so it's allowlisted alongside CountAllDynamicPolicies rather than left implicitly safe. #3319/#3039.",
		"platform/agent/hitl/repository.go::GetByRequestID":                        "BYPASSRLS lookup pool via r.lookup() (#3048) — by-uuid discovery read; the SERVICE post-authorizes (rejectCrossOrg compares the row's OrgID to the authenticated caller before any result leaves or any write runs; R3 BLOCKER-2).",
		"platform/agent/hitl/repository.go::GetHistory":                            "BYPASSRLS lookup pool via r.lookup() (#3048) — the service resolves + org-checks the parent request before this read (R3 BLOCKER-2).",
		"ee/platform/agent/hitl/repository.go::GetByRequestID":                     "BYPASSRLS lookup pool via r.lookup() (#3048) — EE mirror; service rejectCrossOrg post-authorizes (R3 BLOCKER-2).",
		"ee/platform/agent/hitl/repository.go::GetHistory":                         "BYPASSRLS lookup pool via r.lookup() (#3048) — EE mirror; parent org-checked first (R3 BLOCKER-2).",
		"platform/connectors/registry/postgres_storage.go::GetConnector":           "BYPASSRLS lookup pool via s.lookup() (#3048) — internal-only: called solely from Registry.loadFromStorage/ReloadFromStorage with ids from ListConnectors; the tenant-reachable Registry.Get reads only the in-memory map, never storage with a caller id (R3 MEDIUM-4 reachability census).",
		"platform/connectors/registry/postgres_storage.go::ListConnectors":         "BYPASSRLS lookup pool via s.lookup() (#3048) — deployment-wide cross-replica registry sync.",
		"platform/connectors/registry/postgres_storage.go::ListConnectorsByTenant": "BYPASSRLS lookup pool via s.lookup() (#3048) — spans tenant + '*' shared scopes; SQL tenancy predicate preserves isolation on every posture.",

		// ── Admin-pool services by construction (same entries as the write
		// audit's adminPoolAllowlist; the pools are wired via
		// OpenPlatformAdminConnection / h.adminConn() / m.adminDB).
		"platform/agent/marketplace/metering.go::*":                            "admin-pool: marketplace metering runs cross-org (meteringDB = OpenPlatformAdminConnection in run.go). Mirrors write allowlist.",
		"ee/platform/agent/marketplace/metering.go::*":                         "admin-pool: EE mirror of marketplace metering.",
		"platform/agent/node_enforcement/heartbeat.go::GetActiveNodeCount":     "admin-pool: cross-org node census consumed by NodeMonitor + metering, both on OpenPlatformAdminConnection pools (run.go).",
		"platform/agent/node_enforcement/heartbeat.go::GetActiveNodesByOrg":    "admin-pool: reads through the NodeMonitor's platform-admin pool (run.go RequirePlatformAdminOrFatal(\"NodeMonitor\")).",
		"ee/platform/agent/node_enforcement/heartbeat.go::GetActiveNodeCount":  "admin-pool: EE mirror.",
		"ee/platform/agent/node_enforcement/heartbeat.go::GetActiveNodesByOrg": "admin-pool: EE mirror.",
		"platform/agent/node_enforcement/monitor.go::*":                        "admin-pool: NodeMonitor runs on OpenPlatformAdminConnection (run.go RequirePlatformAdminOrFatal(\"NodeMonitor\")); cross-org enforcement sweep.",
		"ee/platform/agent/node_enforcement/monitor.go::*":                     "admin-pool: EE mirror of NodeMonitor.",
		"platform/agent/community_saas_recovery.go::*":                         "admin-pool: cross-org csaas recovery sweep (recoveryDB = OpenPlatformAdminConnection). Mirrors write allowlist.",
		"platform/agent/tenant_delete.go::*":                                   "admin-pool (tracked #2397): GDPR delete surface. Mirrors write allowlist.",
		"platform/orchestrator/audit_cleanup.go::*":                            "admin-pool: cross-org audit/execution retention sweep. Mirrors write allowlist.",
		"platform/orchestrator/sebi/sebi_audit_export_service.go::*":           "admin-pool: SEBI regulatory cross-tenant audit export. Mirrors write allowlist.",
		"ee/platform/customer-portal/api/admin.go::*":                          "admin-pool: h.adminConn() / rejectTierDowngrade receives the admin conn. Mirrors write allowlist.",
		"ee/platform/customer-portal/api/organizations.go::*":                  "admin-pool: h.adminConn() routes to axonflow_platform_admin (falls back with a loud WARN). Mirrors write allowlist.",
		"ee/platform/customer-portal/api/user_tokens.go::mint":                 "admin-pool: h.adminConn() — commented 'cross-org read → admin connection' at the call site (#2924).",
		"ee/platform/customer-portal/api/sso.go::GetSession":                   "admin-pool: s.preAuthDB() — pre-auth lookup by session id alone (v9 Brief 11.5 R3-HIGH-1).",
		"ee/platform/customer-portal/scim/middleware.go::orgForTenant":         "admin-pool: m.adminDB with a documented refuse-to-guess fallback — tenant→org resolution is PRE-ORG (mig 103 FORCE RLS).",

		// ── SECURITY DEFINER helper + documented legacy fallback: the
		// flagged read is the pre-migration fallback branch that only works
		// (by design) on owner pools; the primary path is the helper.
		"ee/platform/customer-portal/api/auth.go::HandleCheckSession":              "mig-118 portal_session_lookup SECURITY DEFINER + documented pre-118 direct-SELECT fallback (#3039).",
		"ee/platform/customer-portal/api/auth.go::HandleLogin":                     "mig-104 portal_auth_lookup_org SECURITY DEFINER + documented pre-104 fallback.",
		"ee/platform/customer-portal/api/auth.go::HandleCheckSSOAvailability":      "mig-104 portal_check_sso_availability SECURITY DEFINER + documented pre-104 fallback.",
		"ee/platform/customer-portal/middleware/dev_auth.go::AuthMiddleware":       "mig-118 portal_session_lookup SECURITY DEFINER + documented pre-118 fallback (#3039); also on the write audit's #2403 list.",
		"platform/agent/community_saas_register.go::validateCommunityRegistration": "mig-105 csaas_auth_lookup SECURITY DEFINER + documented 42883-only fallback (R3-H1 hardened).",

		// ── Pre-auth discovery lookups tracked by #2403 (same entries as
		// the write audit): the credential itself is the lookup key and the
		// resolved row establishes the org.
		//
		// #3163 CORRECTION. The justification here used to argue only
		// DISCLOSURE — "the credential IS the key, so the read yields nothing
		// the caller did not already hold" — and was silent on AVAILABILITY,
		// which is the half that actually bites. A pre-auth read on an
		// RLS-gated table does not merely fail to leak: under app-role it
		// matches zero rows, and ErrNoRows is indistinguishable from a bad
		// credential, so a VALID key is rejected and the operator rotates
		// something that was never wrong. An allowlist entry that reasons only
		// about disclosure will keep re-approving that outcome. The entry
		// stays — the read genuinely cannot carry a GUC — but it now records
		// WHICH pool makes it correct, because "pre-auth" alone does not.
		// #3156 surfaced this by adding the scim_* tables to the gated set. It
		// is the SAME shape as sso.go::GetSession and keys.go::ValidateAPIKey
		// below, and it is already FIXED — #3134 routed it through
		// m.preAuthDB(), the BYPASSRLS platform_admin pool. The walker cannot
		// distinguish preAuthDB() from db at the call site.
		//
		// Availability, not only disclosure: validateToken discovers WHICH
		// tenant owns a presented bearer token, so it is the query that would
		// have to supply app.current_org_id. Unrouted it matches 0 rows under
		// mig 117's RLS and every valid SCIM token is reported invalid. The
		// tenant scope is applied AFTER the token resolves it (updateLastUsed
		// re-asserts it both as an org scope and in the predicate).
		"ee/platform/customer-portal/scim/middleware.go::validateToken": "pre-auth lookup by token_hash (the credential IS the key), routed through m.preAuthDB() — the BYPASSRLS platform_admin pool (#3134). NOT merely a disclosure argument: on the ordinary pool this read matches 0 rows under mig 117's RLS and every valid bearer token is reported invalid (availability). The resolved tenant is the authenticated result and scopes every statement that follows.",

		"ee/platform/customer-portal/api/keys.go::ValidateAPIKey": "pre-auth lookup by key_hash (the credential IS the key), routed through h.preAuthDB() — the BYPASSRLS platform_admin pool (#3163). NOT merely a disclosure argument: on the ordinary pool this read matches 0 rows under mig 018's RLS and every valid key is reported invalid (availability). The resolved org is the authenticated result and scopes the last_used_at write that follows. The AST walker cannot distinguish preAuthDB() from db at the call site, so this is allowlisted with the design intent named — same shape as sso.go::GetSession.",

		// ── Deliberate deployment-wide reads with the constraint documented
		// at the call site.
		"ee/platform/customer-portal/api/usage.go::HandleGetUsageSummary": "deployment-wide usage rollup summary; the call site documents that a single-org GUC cannot express it and the admin pool is not plumbed into UsageHandler — tracked follow-up named in the code comment.",
		"platform/orchestrator/llm/storage.go::GetProvider":               "GUC-self-scoped by explicit `tenant_id = current_setting(...)` predicate — identical behavior on every posture; storage backend not wired into the production registry (run.go constructs llm.NewRegistry without storage).",
		"platform/orchestrator/llm/storage.go::ListAllProviders":          "GUC-self-scoped by explicit predicate — same as GetProvider; not wired in production.",

		// ── Test-only helpers (//nolint:unused), no production callers.
		"platform/agent/db_auth.go::getCustomerUsageForMonth": "//nolint:unused test-only helper; no production callers (same class as the write audit's revokeAPIKey entry).",
		"platform/agent/db_auth.go::createAPIKey":             "//nolint:unused test-only helper; no production callers (write audit precedent).",
	}
	return allowFiles, allowFuncs
}

// TestRLSReadAuditHelpers unit-covers the read-audit machinery so a refactor
// of the matcher/resolver surfaces here BEFORE the integration walk passes
// for unrelated reasons (mirror of TestRLSWriteAuditHelpers).
func TestRLSReadAuditHelpers(t *testing.T) {
	tables := map[string]bool{
		"static_policies": true, "policy_overrides": true, "hitl_approval_queue": true,
	}

	t.Run("matchRLSReadTables", func(t *testing.T) {
		cases := []struct {
			sql  string
			want []string
		}{
			{"SELECT * FROM static_policies WHERE policy_id = $1", []string{"static_policies"}},
			{"SELECT sp.id FROM static_policies sp LEFT JOIN policy_overrides po ON true", []string{"static_policies", "policy_overrides"}},
			// DELETE head is the write audit's territory…
			{"DELETE FROM policy_overrides WHERE id = $1", nil},
			// …but a sub-SELECT inside a write still counts as a read.
			{"INSERT INTO audit_logs SELECT * FROM hitl_approval_queue", []string{"hitl_approval_queue"}},
			// Schema-qualified + quoted forms normalize.
			{`SELECT 1 FROM public."static_policies"`, []string{"static_policies"}},
			// Non-RLS tables don't match; EXTRACT(x FROM col) is harmless.
			{"SELECT EXTRACT(EPOCH FROM created_at) FROM audit_logs", nil},
			{"SELECT set_config('app.current_org_id', $1, true)", nil},
		}
		for _, c := range cases {
			got := matchRLSReadTables(c.sql, tables)
			if len(got) != len(c.want) {
				t.Errorf("matchRLSReadTables(%q) = %v, want %v", c.sql, got, c.want)
				continue
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("matchRLSReadTables(%q) = %v, want %v", c.sql, got, c.want)
					break
				}
			}
		}
	})

	t.Run("resolveReadSQLArg resolves Sprintf format literals", func(t *testing.T) {
		src := `package x
func f(db *sql.DB) {
	q := fmt.Sprintf("SELECT id FROM static_policies WHERE %s", where)
	_ = q
	db.QueryContext(ctx, fmt.Sprintf("SELECT id FROM policy_overrides WHERE %s", where))
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
		if fn == nil {
			t.Fatal("synth FuncDecl missing")
		}
		findings := auditReadFunc("x.go", "f", fn, fset, map[string]bool{"policy_overrides": true, "static_policies": true})
		// The inline-Sprintf QueryContext must be flagged (the #3048 List
		// readers were exactly this shape); the bound-but-unused q is not a
		// DB call and must not be.
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding (inline Sprintf query), got %d: %v", len(findings), findings)
		}
		if !strings.Contains(findings[0], "policy_overrides") {
			t.Errorf("finding should name policy_overrides: %s", findings[0])
		}
	})

	t.Run("tx receiver exempt, pool receiver flagged", func(t *testing.T) {
		src := `package x
func g(db *sql.DB, tx *sql.Tx) {
	tx.QueryRowContext(ctx, "SELECT id FROM static_policies WHERE policy_id = $1")
	db.QueryRowContext(ctx, "SELECT id FROM static_policies WHERE policy_id = $1")
}`
		fset := token.NewFileSet()
		fileNode, err := parser.ParseFile(fset, "synth.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse synth: %v", err)
		}
		var fn *ast.FuncDecl
		for _, decl := range fileNode.Decls {
			if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "g" {
				fn = f
			}
		}
		findings := auditReadFunc("x.go", "g", fn, fset, map[string]bool{"static_policies": true})
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding (pool receiver only), got %d: %v", len(findings), findings)
		}
	})
}
