// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package tenantscope

import (
	"go/ast"
	"go/parser"
	"go/printer"
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

// TestNoFailOpenOrgCompare is the syntactic guard that makes site nine of the
// #3065 class fail the build.
//
// The class is one idiom:
//
//	if callerOrg != "" && row.OrgID != "" && row.OrgID != callerOrg { reject }
//
// It reads like a tenancy check and behaves like one — right up to the moment
// either side is empty, at which point it authorizes everything. Eight call
// sites carried it. The forensic reconciliation in #3071 found that this
// class has recurred five times because every prior fix was a census of the
// doors a review happened to name; the ninth door is always the one nobody
// listed. A census cannot be complete by construction. A syntactic rule can.
//
// Two shapes are flagged:
//
//  1. Go: a `&&` chain that empty-checks two expressions and then compares
//     those same two expressions for inequality, where at least one names a
//     tenancy key (org / tenant / client). The tenancy-name requirement is
//     what keeps the rule off legitimately-identical shapes elsewhere — e.g.
//     the PII masking check `d.Value != "" && d.MaskedValue != "" &&
//     d.MaskedValue != d.Value`, which is not an authorization decision.
//
//  2. SQL: a string literal containing the same disjunction expressed as a
//     WHERE clause — `AND ($2 = ” OR org_id IS NULL OR org_id = ” OR
//     org_id = $2)`. This shape is in the rule because #3065's F4 proved the
//     idiom SURVIVES A CHANGE OF LANGUAGE: the #2934 fix moved the fail-open
//     compare into SQL while its own comment claimed the check was "isolated
//     in the SQL WHERE clause — never post-fetch". A Go-only rule would have
//     declared that site clean.
//
// The fix for a finding is never to restate the compare more carefully; it is
// to route the decision through Scope.Authorize / Scope.AuthorizeOrgOnly,
// which fail closed when either side is empty.
func TestNoFailOpenOrgCompare(t *testing.T) {
	var findings []string
	allow := failOpenAllowlist()

	forEachSourceFile(t, func(rel string, fset *token.FileSet, f *ast.File, src []byte) {
		for _, decl := range f.Decls {
			// Package-level const/var declarations hold SQL too — the #3065
			// F4 fragment itself lived in a top-level `const budgetOrgScopeSQL`.
			// A FuncDecl-only walk would have declared that site clean, which
			// is the failure mode this whole test exists to prevent.
			if gd, isGen := decl.(*ast.GenDecl); isGen {
				for _, spec := range gd.Specs {
					vs, isVal := spec.(*ast.ValueSpec)
					if !isVal {
						continue
					}
					name := "<decl>"
					if len(vs.Names) > 0 {
						name = vs.Names[0].Name
					}
					qualified := rel + "::" + name
					if reason, allowed := allow[qualified]; allowed {
						t.Logf("allowlisted: %s — %s", qualified, reason)
						continue
					}
					for _, lit := range stringLiterals(vs) {
						sql, err := strconv.Unquote(lit.Value)
						if err != nil {
							sql = lit.Value
						}
						if why, bad := failOpenSQL(sql); bad {
							findings = append(findings,
								qualified+" ("+rel+":"+strconv.Itoa(fset.Position(lit.Pos()).Line)+"): "+why)
						}
					}
				}
				continue
			}

			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			qualified := rel + "::" + fn.Name.Name
			if reason, allowed := allow[qualified]; allowed {
				t.Logf("allowlisted: %s — %s", qualified, reason)
				continue
			}

			ast.Inspect(fn, func(n ast.Node) bool {
				be, ok := n.(*ast.BinaryExpr)
				if !ok || (be.Op != token.LAND && be.Op != token.LOR) {
					return true
				}
				// Only inspect the OUTERMOST node of a chain, so a 3-term
				// chain produces one finding rather than two.
				if parentIsBoolChain(fn, be) {
					return true
				}
				// #3065 R3 round 1: BOTH polarities. The reject form is
				//   a != "" && b != "" && b != a
				// and the equally natural allow form — how an isAuthorized
				// helper gets written — is its De Morgan dual
				//   a == "" || b == "" || b == a
				// A rule that only walked && caught the first and waved the
				// second straight through.
				if why, bad := failOpenChain(fset, be.Op, flattenBoolChain(be)); bad {
					findings = append(findings,
						qualified+" ("+rel+":"+strconv.Itoa(fset.Position(be.Pos()).Line)+"): "+why)
				}
				return true
			})

			for _, lit := range stringLiterals(fn) {
				sql, err := strconv.Unquote(lit.Value)
				if err != nil {
					// Raw backtick strings Unquote rejects are rare; fall back
					// to the raw token so SQL in them is still scanned.
					sql = lit.Value
				}
				if why, bad := failOpenSQL(sql); bad {
					findings = append(findings,
						qualified+" ("+rel+":"+strconv.Itoa(fset.Position(lit.Pos()).Line)+"): "+why)
				}
			}
		}
	})

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf(
			"fail-open tenancy compare detected (#3065, epic #3071 Tier 2). %d site(s) authorize "+
				"a tenancy decision with a comparison that PASSES when either side is empty — and "+
				"\"empty\" is caller-selectable, because the caller's org arrives as a header they "+
				"can simply omit.\n\n"+
				"Fix: route the decision through tenantscope.Scope.Authorize(rowOrg, rowTenant) or "+
				"Scope.AuthorizeOrgOnly(rowOrg), both of which deny when either side is empty. Do not "+
				"restate the comparison.\n\nFindings:\n  - %s",
			len(findings), strings.Join(findings, "\n  - "))
	}
}

// TestAuthorizeOrgOnlyCallSitesArePinned pins the surfaces that authorize on
// the org dimension alone.
//
// AuthorizeOrgOnly is the deliberate escape hatch for tables whose rows carry
// no reliable tenant key. It is strictly weaker than Authorize, so an
// unnoticed drift from one to the other is how a two-dimension boundary
// quietly becomes a one-dimension boundary. Adding a call site is fine — it
// just has to be a visible, reviewed line in this list rather than a diff
// nobody reads twice.
func TestAuthorizeOrgOnlyCallSitesArePinned(t *testing.T) {
	// file → why the tenant dimension is not consulted there.
	pinned := map[string]string{
		"platform/orchestrator/planning/service.go":                 "plans: the by-id call sites thread a bare orgID string; GetPlanForExecution's signature is fixed by a call site outside this workstream's region of run.go, and plans.org_id has always been the plan tenancy key",
		"platform/orchestrator/workflow_control/mock_repository.go": "mock list filter: mirrors the Postgres List predicate, which applies each tenancy dimension independently",
		"platform/agent/policy_override_repository.go":              "policy_overrides: rows are keyed on org_id (mig 110 RLS key); the table's tenant_id is a legacy nullable scope-narrowing column, not an ownership key",
		"platform/agent/hitl/service.go":                            "hitl_approval_queue: rejectCrossOrg keys on the request's org_id, the same key mig 110-era RLS and the #3048 R3 forgery guard use",
		"ee/platform/agent/hitl/service.go":                         "enterprise copy of the above — kept in lockstep because ee/ overrides platform/ at Docker build",
		"platform/orchestrator/unified_execution_handler.go":        "execution_history: the row HAS a reliable tenant_id, and the credential-scoped caller is still authorized on BOTH dimensions. The org-only form is reached only for a caller carrying the trusted X-Axonflow-Tenancy-Scope: org assertion (#3367), whose authority IS the org and which holds no credential id to compare: the row's tenant_id is the EXECUTING caller's Basic-auth username (mig 049 dropped the organizations FK for that reason; mig 092 calls it a deprecated alias of client_id), so comparing it to a portal session's display-default tenant 404'd every execution the session was entitled to open. Read paths only: the write path (CancelExecution) uses checkTenantOwnershipStrict and keeps the two-dimension compare",
	}

	found := map[string]int{}
	forEachSourceFile(t, func(rel string, fset *token.FileSet, f *ast.File, src []byte) {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "AuthorizeOrgOnly" {
				found[rel]++
			}
			return true
		})
	})

	for rel := range found {
		if _, ok := pinned[rel]; !ok {
			t.Errorf("unpinned AuthorizeOrgOnly call site in %s.\n"+
				"AuthorizeOrgOnly ignores the row's tenant key and is therefore strictly weaker than "+
				"Authorize. If that is correct for this table, add %q to the pinned map in "+
				"TestAuthorizeOrgOnlyCallSitesArePinned with a one-line reason naming why the table "+
				"has no reliable tenant key. If it is not, use Authorize.", rel, rel)
		}
	}
	for rel := range pinned {
		if found[rel] == 0 && fileExists(t, rel) {
			t.Errorf("stale pin: %s no longer calls AuthorizeOrgOnly — remove it from the pinned map "+
				"so the list keeps meaning something", rel)
		}
	}
}

// failOpenAllowlist names the functions whose fail-open-shaped predicate is
// NOT an authorization decision. Discipline, borrowed from the RLS read audit:
// every entry carries a one-line justification naming why the empty value
// cannot be chosen by a caller. "Pre-existing" is not a justification.
func failOpenAllowlist() map[string]string {
	return map[string]string{
		"platform/orchestrator/cost/postgres_repository.go::GetBudgetsForScope": "enforcement plane, not an authorization boundary: admitting an unstamped budget row applies a DEPLOYMENT-GLOBAL spend cap to every tenant, which only ever tightens spend. Constraining it would silently disable those caps on upgrade. #3065's budget exposure is the by-id path (GetBudgetScoped / DeleteBudgetScoped / UpdateBudget), which is strict-equality and refuses an unbound caller.",
		"platform/orchestrator/cost/postgres_repository.go::GetUsageForPeriod":  "the org/tenant arguments are DB-sourced, not request-sourced: Service.statusForBudget / checkBudgetsForScope pass budget.OrgID / budget.TenantID straight from a row GetBudgetsForScope selected, so the empty value is not caller-selectable here. The result is a scalar SUM used to evaluate a budget the caller was already authorized for; it discloses no rows and identifies no tenant.",

		// #3065 R3 round 1: `(tenant_id = $n OR tenant_id IS NULL)` on
		// policy_overrides is the ORG-LEVEL override selector, not a fail-open
		// tenancy filter — an org-scoped override is stored with tenant_id
		// NULL by design (PolicyOverrideRepository.Create), and every one of
		// these reads runs inside WithOrgScope(scopeOrg), so RLS bounds the
		// result to the caller's org before the tenant disjunct is evaluated.
		// The disjunct widens WITHIN an org, never across one.
		"platform/agent/mcp_richer_context.go::lookupActiveOverride":        "org-level override selector (tenant_id IS NULL is the org-scope form), inside WithOrgScope — widens within the caller's org, never across orgs. R3 round 2: the OTHER branch of this function ran the same predicate as a BARE read when the caller org was unknown, which on an owner-pool deployment resolved any org's override; that branch now returns no-override rather than querying, so this entry vouches only for the wrapped query.",
		"platform/orchestrator/override_enforcement.go::FindActiveOverride": "same shape and same WithOrgScope wrap as lookupActiveOverride above",
	}
}

// --- helpers ---------------------------------------------------------------

// tenancyIdentRE-equivalent: an expression names a tenancy key when its
// rendered text mentions org, tenant, or client id. Deliberately broad — a
// false positive costs one allowlist-free rewrite through Authorize, a false
// negative costs a cross-tenant write.
func namesTenancy(expr string) bool {
	l := strings.ToLower(expr)
	for _, needle := range []string{"org", "tenant", "clientid", "client_id"} {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func render(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, e); err != nil {
		return ""
	}
	return sb.String()
}

func isEmptyStringLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}

func flattenBoolChain(e ast.Expr) []ast.Expr {
	be, ok := e.(*ast.BinaryExpr)
	if !ok || (be.Op != token.LAND && be.Op != token.LOR) {
		return []ast.Expr{e}
	}
	return append(flattenBoolChain(be.X), flattenBoolChain(be.Y)...)
}

// parentIsBoolChain reports whether be is nested inside another &&/|| chain of
// the same operator, so only the outermost node is analysed.
func parentIsBoolChain(root ast.Node, be *ast.BinaryExpr) bool {
	nested := false
	ast.Inspect(root, func(n ast.Node) bool {
		outer, ok := n.(*ast.BinaryExpr)
		if !ok || outer == be || outer.Op != be.Op {
			return true
		}
		if outer.X == ast.Expr(be) || outer.Y == ast.Expr(be) {
			nested = true
		}
		return true
	})
	return nested
}

// isEmptinessTest reports whether a term tests `x` for emptiness in the given
// polarity, returning the rendered `x`.
//
// #3065 R3 round 1: the first version required a literal `""` on one side,
// which meant `len(x) > 0`, `len(x) == 0`, `x != emptyConst` and
// `notEmpty(x)` all evaded the rule. Emptiness has more than one spelling and
// the rule has to know all of the common ones.
func isEmptinessTest(fset *token.FileSet, e ast.Expr, wantNonEmpty bool) (string, bool) {
	switch t := e.(type) {
	case *ast.BinaryExpr:
		// x != "" / x == ""  (either operand order)
		if t.Op == token.NEQ || t.Op == token.EQL {
			nonEmpty := t.Op == token.NEQ
			if isEmptyStringLit(t.Y) {
				return render(fset, t.X), nonEmpty == wantNonEmpty
			}
			if isEmptyStringLit(t.X) {
				return render(fset, t.Y), nonEmpty == wantNonEmpty
			}
			// x != someEmptyIdent — a named empty constant is still an
			// emptiness test as far as this rule is concerned.
			if id, ok := t.Y.(*ast.Ident); ok && looksEmptyNamed(id.Name) {
				return render(fset, t.X), nonEmpty == wantNonEmpty
			}
		}
		// len(x) > 0 / len(x) != 0 / len(x) == 0
		if lenArg, ok := lenCallArg(fset, t.X); ok {
			if lit, isLit := t.Y.(*ast.BasicLit); isLit && lit.Value == "0" {
				switch t.Op {
				case token.GTR, token.NEQ:
					return lenArg, wantNonEmpty
				case token.EQL, token.LEQ:
					return lenArg, !wantNonEmpty
				}
			}
		}
	case *ast.CallExpr:
		// notEmpty(x) / isSet(x) / hasOrg(x) — a helper whose NAME says
		// emptiness. Deliberately generous: a false positive costs one
		// rewrite through Authorize, a false negative costs a tenant.
		if name, arg, ok := unaryPredicate(fset, t); ok && looksEmptinessPredicate(name) {
			return arg, wantNonEmpty
		}
	case *ast.UnaryExpr:
		// !isEmpty(x)
		if t.Op == token.NOT {
			if inner, ok := t.X.(*ast.CallExpr); ok {
				if name, arg, okc := unaryPredicate(fset, inner); okc && looksEmptinessPredicate(name) {
					return arg, wantNonEmpty
				}
			}
		}
	}
	return "", false
}

func looksEmptyNamed(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "empty") || strings.Contains(l, "blank")
}

func looksEmptinessPredicate(name string) bool {
	l := strings.ToLower(name)
	for _, needle := range []string{"empty", "blank", "isset", "present", "usable", "bound", "has", "notnull"} {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func lenCallArg(fset *token.FileSet, e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "len" {
		return "", false
	}
	return render(fset, call.Args[0]), true
}

func unaryPredicate(fset *token.FileSet, call *ast.CallExpr) (name, arg string, ok bool) {
	if len(call.Args) != 1 {
		return "", "", false
	}
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name, render(fset, call.Args[0]), true
	case *ast.SelectorExpr:
		return f.Sel.Name, render(fset, call.Args[0]), true
	}
	return "", "", false
}

// failOpenChain reports whether a boolean chain guards a tenancy comparison
// behind emptiness tests, in either polarity:
//
//	REJECT form (op = &&): a != "" && b != "" && b != a
//	ALLOW  form (op = ||): a == "" || b == "" || b == a
//
// Both mean "if either side is empty, authorize". The comparison operator that
// completes the shape is NEQ in the && form and EQL in the || form.
func failOpenChain(fset *token.FileSet, op token.Token, terms []ast.Expr) (string, bool) {
	wantNonEmpty := op == token.LAND
	compareOp := token.NEQ
	if op == token.LOR {
		compareOp = token.EQL
	}

	emptyChecked := map[string]bool{}
	type cmp struct{ left, right string }
	var crossCompares []cmp

	for _, c := range terms {
		if name, ok := isEmptinessTest(fset, c, wantNonEmpty); ok {
			emptyChecked[name] = true
			continue
		}
		be, ok := c.(*ast.BinaryExpr)
		if !ok || be.Op != compareOp {
			continue
		}
		if _, isLit := be.X.(*ast.BasicLit); isLit {
			continue
		}
		if _, isLit := be.Y.(*ast.BasicLit); isLit {
			continue
		}
		crossCompares = append(crossCompares, cmp{render(fset, be.X), render(fset, be.Y)})
	}

	for _, c := range crossCompares {
		if !emptyChecked[c.left] || !emptyChecked[c.right] {
			continue
		}
		if !namesTenancy(c.left) && !namesTenancy(c.right) {
			continue
		}
		shape := c.left + ` != "" && ` + c.right + ` != "" && ` + c.left + " != " + c.right
		if op == token.LOR {
			shape = c.left + ` == "" || ` + c.right + ` == "" || ` + c.left + " == " + c.right
		}
		return "fail-open tenancy compare `" + shape +
			"` — this authorizes when EITHER side is empty, and the caller chooses \"empty\" by " +
			"omitting a header", true
	}
	return "", false
}

// normalizeSQL uppercases, strips parentheses and collapses whitespace so the
// disjunct patterns below can be matched positionally.
//
// Parentheses are removed deliberately: `(org_id = $5 OR (org_id IS NULL AND
// $5 = ”))` and `(org_id = $3 OR org_id IS NULL)` differ only in whether the
// NULL branch is guarded by an AND, and that distinction survives paren
// removal while the noise does not.
func normalizeSQL(s string) string {
	r := strings.NewReplacer("(", " ", ")", " ", "\n", " ", "\t", " ")
	return strings.Join(strings.Fields(strings.ToUpper(r.Replace(s))), " ")
}

var (
	// `OR org_id IS NULL` as a BARE disjunct — the capture is the token that
	// follows, so an AND-guarded branch (`OR (org_id IS NULL AND $5 = '')`,
	// which only admits the NULL row when the caller is also empty) is not
	// flagged.
	sqlNullDisjunctRE = regexp.MustCompile(`\bOR\s+(?:\w+\.)?(?:ORG_ID|TENANT_ID|ORGANIZATION_ID|CLIENT_ID)\s+IS\s+NULL\s*(\w*)`)
	// `OR org_id = ''` — admits the unowned row unconditionally.
	sqlEmptyDisjunctRE = regexp.MustCompile(`\bOR\s+(?:\w+\.)?(?:ORG_ID|TENANT_ID|ORGANIZATION_ID|CLIENT_ID)\s*=\s*''`)
	// The genuinely guarded NULL branch: `OR (org_id IS NULL AND $5 = '')`
	// admits the unstamped row only when the caller is ALSO empty, so it never
	// exposes another tenant's stamped row.
	sqlGuardedNullRE = regexp.MustCompile(`IS\s+NULL\s+AND\s+\$\d+\s*=\s*''`)

	// `$2 = '' OR <tenancy column> ...` — admits EVERY row when the caller
	// supplies nothing. This is the exact fragment #3065's F4 was. The
	// tenancy-column requirement keeps the rule off legitimate OPTIONAL
	// narrowing filters on non-tenancy columns (e.g. `$2 = '' OR user_id = $2`).
	sqlCallerEmptyRE = regexp.MustCompile(`\$\d+\s*=\s*''\s+OR\s+(?:\w+\.)?(?:ORG_ID|TENANT_ID|ORGANIZATION_ID|CLIENT_ID)\b`)
)

// failOpenSQL reports the same idiom expressed as a SQL WHERE fragment.
func failOpenSQL(s string) (string, bool) {
	n := normalizeSQL(s)
	if !strings.Contains(n, "ORG_ID") && !strings.Contains(n, "TENANT_ID") &&
		!strings.Contains(n, "ORGANIZATION_ID") && !strings.Contains(n, "CLIENT_ID") {
		return "", false
	}

	for _, m := range sqlNullDisjunctRE.FindAllStringSubmatch(n, -1) {
		// #3065 R3 round 1: `AND` alone is not proof of a guarded branch —
		// parenthesis-stripping turns `(org_id = $2 OR org_id IS NULL) AND
		// active = true` into the same token sequence as the genuinely
		// guarded `OR (org_id IS NULL AND $2 = '')`. Require that the AND be
		// followed by a comparison against the caller PARAMETER, which is
		// what makes the branch conditional on the caller also being empty.
		if strings.EqualFold(m[1], "AND") && sqlGuardedNullRE.MatchString(n) {
			continue
		}
		return "fail-open tenancy predicate in SQL: a bare `OR <tenancy column> IS NULL` disjunct " +
			"admits rows that carry no tenancy key, i.e. rows every tenant can reach", true
	}
	if sqlEmptyDisjunctRE.MatchString(n) {
		return "fail-open tenancy predicate in SQL: a bare `OR <tenancy column> = ''` disjunct " +
			"admits rows that carry no tenancy key, i.e. rows every tenant can reach", true
	}
	if sqlCallerEmptyRE.MatchString(n) {
		return "fail-open tenancy predicate in SQL: a `$n = ''` disjunct disables the tenancy " +
			"filter entirely when the caller supplies nothing — this is #3065 F4 verbatim. Refuse " +
			"an unbound caller before issuing the query and compare with strict equality", true
	}
	return "", false
}

func stringLiterals(f ast.Node) []*ast.BasicLit {
	var out []*ast.BasicLit
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			out = append(out, lit)
		}
		return true
	})
	return out
}

func fileExists(t *testing.T, rel string) bool {
	t.Helper()
	root, err := lintRepoRoot()
	if err != nil {
		return false
	}
	_, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return statErr == nil
}

// forEachSourceFile walks every non-test .go file under platform/ and
// ee/platform/ (the latter is absent on community-mirror checkouts) and hands
// each to fn with its repo-relative slash path.
func forEachSourceFile(t *testing.T, fn func(rel string, fset *token.FileSet, f *ast.File, src []byte)) {
	t.Helper()
	repoRoot, err := lintRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	for _, root := range []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	} {
		if _, statErr := os.Stat(root); os.IsNotExist(statErr) {
			t.Logf("scan dir %s not present in this checkout (likely community sync); skipping", root)
			continue
		}
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)

			src, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("%s: read: %v", rel, readErr)
				return nil
			}
			fset := token.NewFileSet()
			parsed, parseErr := parser.ParseFile(fset, path, src, parser.ParseComments)
			if parseErr != nil {
				t.Errorf("%s: parse: %v", rel, parseErr)
				return nil
			}
			fn(rel, fset, parsed, src)
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", root, walkErr)
		}
	}
}

// lintRepoRoot anchors on the presence of `platform/`, matching
// findRepoRoot's contract in the agent package. `ee/platform/` is excluded
// from the community sync filter, so anchoring on it would fail on
// community-mirror checkouts.
func lintRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		st, statErr := os.Stat(filepath.Join(dir, "platform"))
		if statErr == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
