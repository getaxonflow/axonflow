// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacyfreeze

// THE WRITER CENSUS (#4084, #4088): every HTTP handler that can reach a write
// of a frozen table must answer the freeze through Answer.
//
// # WHY THIS EXISTS
//
// core/172 froze the two legacy policy tables, and the refusal reached
// customers as a bare 500 on one surface after another: the orchestrator's
// policy routes (#4010), then its deprecated family (#4036), then the agent's
// system-policy routes (#4084) and template apply (#4088). Each was found by a
// person reading, the last two by a reviewer sweeping every writer of the two
// tables with a planted control. This is that sweep, mechanised, so the next
// surface is a red test rather than a customer's 500.
//
// # WHAT IT DERIVES, AND WHAT IT DOES NOT ENUMERATE
//
// Nothing below names a write site or a route. The census:
//
//  1. type-checks every non-test package of every module that is
//     axonflow/platform, requires it, or is one it REPLACES with a local
//     directory (platform/decision today), under each build tag set
//     (platform/testutil/gocensus);
//  2. marks as a SINK every function whose body EXECUTES a statement writing a
//     frozen table: INSERT INTO, UPDATE [ONLY], DELETE FROM [ONLY], MERGE INTO,
//     COPY ... FROM or TRUNCATE, schema-qualified or quoted. The statement may be
//     a literal, a named constant, a constant concatenation, or a package-level
//     variable of ANY package whose initialiser holds one - a string, a map
//     value, a struct field. A declaration is not a sink; the function that
//     uses it is. The table names are this package's frozenTables, the list the
//     classifier itself reads, so the census and the classifier cannot disagree
//     about what is frozen;
//  3. builds the call graph from types.Info.Uses - so a function taken as a
//     VALUE still counts - plus, for a call through an interface, an edge to
//     that method on every concrete type in the program that implements the
//     interface;
//  4. walks UP from every sink, stopping at the first HTTP handler (anything
//     taking an http.ResponseWriter and an *http.Request, a function literal
//     included) and at any function nothing calls.
//
// Every handler reached must call Answer, directly or through a function that
// does. Every other entry the walk reaches must be in nonHTTPEntries with the
// reason it is not a customer surface, and every row there must still be
// reached, so the list cannot outlive its reason.
//
// # ONE GRAPH PER BUILD CONFIGURATION
//
// The community and enterprise builds are separate programs, and each is
// judged on its own. A handler with build-tag twins - X_community.go and
// X_enterprise.go defining the same function - is one node per build, so the
// twin that answers cannot vouch for the twin that does not. A graph merged
// across builds would union their flags and ship a bare 500 in the build that
// forgot (R3 round one, F3).
//
// # WHAT IT CANNOT SEE, STATED RATHER THAN LEFT TO BE DISCOVERED
//
//   - A statement assembled at run time from a NON-constant: a table name
//     taken from configuration or from information_schema, a query built with
//     fmt.Sprintf over a variable, SQL read from a file or an embedded asset.
//     That shape exists (community_saas_sweep.go's cascade) and is pinned by
//     the mechanism, in platform/agent/legacy_policy_read_only_realpg_test.go.
//   - A table name supplied as a SEPARATE constant from the verb:
//     fmt.Sprintf("INSERT INTO %s", "dynamic_policies"), strings.Join, or
//     pq.CopyIn("dynamic_policies", ...), which builds its COPY at run time.
//     Neither half is a statement on its own; the one Sprintf-built write in
//     the tree is the community_saas_sweep cascade above.
//   - A write through an auto-updatable VIEW over static_policies. The revoke
//     on the table does not close a view, and enforce_legacy_policy_read_only()
//     does; that is asserted by mechanism in
//     platform/agent/legacy_policy_read_only_realpg_test.go, the same boundary
//     the shell census states.
//   - A statement whose verbs are not UPPER case. Every real query in this
//     tree spells them that way and prose does not; the shell census makes the
//     same bet. A case-insensitive match reported seedDefaultData's log line
//     "may not INSERT into dynamic_policies" as a write, which is the prose it
//     would have to be taught to ignore one message at a time.
//   - A call through a func-typed variable or field. The function's name is
//     still USED where the value is taken, so the edge exists from there;
//     what is lost is only which caller invokes it.
//   - WHETHER a classified handler calls Answer on the error path that
//     reaches the write. This census proves the handler holds the answer; the
//     per-surface tests and the runtime legs in 3039 and 3059 prove it is the
//     answer the caller receives.
//
// It is the ENTRY-POINT half of a pair. tests/regression-test-required/
// legacy_policy_write_surface_test.sh pins the write STATEMENTS by digest and
// says nothing about who reaches them; this says nothing about how many
// statements there are and everything about who reaches them. Neither
// re-enumerates the other.

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil/gocensus"
)

const (
	platformModule = "axonflow/platform"
	thisPackage    = "axonflow/platform/shared/legacyfreeze"
	answerKey      = thisPackage + ".Answer"
	refuseKey      = thisPackage + ".RefuseOverride"
)

// frozenWriteRE matches a SQL statement that writes a frozen table, built from
// frozenTables, the classifier's own list.
//
// It is deliberately wider than the shell census, which matches an upper-case
// verb and the table separated by one space on one line: a constant value is
// not a line of source, and the spellings a query builder produces are not a
// reviewer's. So it takes any whitespace (newlines included), the ONLY
// modifier, MERGE, COPY ... FROM, TRUNCATE with a table list, a public schema,
// and a quoted identifier - and the name must still END where the table name
// ends. Two shapes are deliberately NOT writes: COPY ... TO is an export, and
// a privilege string such as "REVOKE ..., TRUNCATE ON static_policies" names a
// verb it does not execute; TRUNCATE therefore requires a table list, not any
// text before the name. The verbs stay UPPER case: see "WHAT IT CANNOT SEE".
var frozenWriteRE = func() *regexp.Regexp {
	table := `(?:"?public"?\s*\.\s*)?"?(?:` + strings.Join(frozenTables, "|") + `)"?(?:[^A-Za-z0-9_"]|$)`
	return regexp.MustCompile(`(?s)` +
		`\b(?:INSERT\s+INTO|UPDATE(?:\s+ONLY)?|DELETE\s+FROM(?:\s+ONLY)?|MERGE\s+INTO)\s+` + table +
		`|\bCOPY\s+` + table + `[^;]*?\bFROM\b` +
		`|\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(?:[A-Za-z0-9_."]+\s*,\s*)*` + table)
}()

// nonHTTPEntries are the entries the walk reaches that are not HTTP handlers,
// each with the reason it is not a customer surface that owes a caller the
// freeze's answer.
//
// KEYED ON THE (ENTRY, SINK) PAIR, NOT ON THE ENTRY. The process entry point
// is legitimately here, and a row saying only "main is exempt" would wave
// through every frozen write main ever reaches - including a new boot path
// that would fail on every application-role deployment. A pair row exempts the
// one write it was reasoned about.
var nonHTTPEntries = map[string]string{
	"axonflow/platform/cmd/orchestrator.main -> (*axonflow/platform/orchestrator.DatabaseDynamicPolicyEngine).insertSamplePolicies": "SAMPLE " +
		"SEEDING AT CONNECT, not a customer surface. connectDB seeds the dev sample policies when the dynamic engine " +
		"starts, and again from refreshPolicies whenever the engine has no live pool - on the refresh tick, or on a " +
		"handler's synchronous refresh after the database was unreachable. It never answers a caller: connectDB logs a " +
		"seed error and returns nil. It seeds only an EMPTY table, and it asks has_table_privilege first, so under " +
		"core/172 it logs that seeding was skipped and attempts no write. The orchestrator policy handlers the walk " +
		"also finds reaching it are classified for their own writes.",
}

// pairKey names one (entry, sink) pair the way nonHTTPEntries keys it.
func pairKey(entry, sink string) string { return entry + " -> " + sink }

// overrideRefusers are the policy override write routes, which refuse at the
// handler (PRD v11 §1.5): the agent's per-policy routes (W3-I item 9, master's
// ruling Q3) and, since #4252, the orchestrator's session override routes.
// policy_overrides is handler-refused: it is deliberately NOT in frozenTables,
// because core/172 does not revoke it, and its writers were deleted rather than
// censused. No sink leads the walk to these routes, so they are declared
// instead, and each must call RefuseOverride.
var overrideRefusers = []string{
	"(*axonflow/platform/agent.StaticPolicyAPIHandler).HandleCreateOverride",
	"(*axonflow/platform/agent.StaticPolicyAPIHandler).HandleDeleteOverride",
	"axonflow/platform/orchestrator.createOverrideHandler",
	"axonflow/platform/orchestrator.revokeOverrideHandler",
}

// expectedClassifiedHandlers is the census's built-in POSITIVE CONTROL: the
// handlers of the two surfaces this census was built from. The walk must reach
// each of them from a sink, in every build that loads the platform module, and
// find it classified. If it reaches none, it is not looking, and its silence
// about every other handler means nothing.
var expectedClassifiedHandlers = []string{
	"(*axonflow/platform/agent.StaticPolicyAPIHandler).HandleCreateStaticPolicy",
	"(*axonflow/platform/agent.StaticPolicyAPIHandler).HandleUpdateStaticPolicy",
	"(*axonflow/platform/agent.StaticPolicyAPIHandler).HandleDeleteStaticPolicy",
	"(*axonflow/platform/agent.StaticPolicyAPIHandler).HandleTogglePolicy",
	"(*axonflow/platform/orchestrator.TemplateAPIHandler).HandleApplyTemplate",
}

// fnNode is one function in the call graph.
type fnNode struct {
	pos     string
	sink    bool
	handler bool
	// answers is true when the body references Answer itself.
	answers bool
	// refuses is true when the body references RefuseOverride itself.
	refuses bool
	calls   map[string]bool
}

// ifaceUse is a reference to an interface method: the method, and the whole
// method set of the interface it was called through. It is resolved after
// every package is loaded, to that method on each concrete type that
// IMPLEMENTS the interface.
type ifaceUse struct {
	caller, method string
	iface          []string
}

// callGraph is ONE build configuration's program. Packages from any number of
// modules accumulate into it; nodes are keyed by types.Func.FullName, which is
// stable across the separate type-checking sessions each module needs.
type callGraph struct {
	nodes   map[string]*fnNode
	pending map[string]ifaceUse
	// methodsOf maps a concrete named type to its pointer method set: each
	// methodKey to the FullName of the method that answers it.
	methodsOf map[string]map[string]string
	// typesWith indexes methodsOf by methodKey, so resolving a call looks only
	// at the types that have that method at all.
	typesWith map[string]map[string]bool
	// sqlVars are the package-level variables, of any package, whose
	// initialiser holds a frozen write; varUses records which function reads
	// which package-level variable. Both are keyed by pkgVarKey and joined in
	// resolve, because the package that USES a variable may be checked before
	// the package that declares it.
	sqlVars map[string]bool
	varUses map[string]map[string]bool
}

func newCallGraph() *callGraph {
	return &callGraph{
		nodes:     map[string]*fnNode{},
		pending:   map[string]ifaceUse{},
		methodsOf: map[string]map[string]string{},
		typesWith: map[string]map[string]bool{},
		sqlVars:   map[string]bool{},
		varUses:   map[string]map[string]bool{},
	}
}

func (g *callGraph) node(key, pos string) *fnNode {
	n := g.nodes[key]
	if n == nil {
		n = &fnNode{pos: pos, calls: map[string]bool{}}
		g.nodes[key] = n
	}
	return n
}

// methodKey renders a method's name and the TYPES of its signature - receiver
// and parameter names excluded - fully qualified, so the same method compares
// equal across sessions.
//
// THE NAMES ARE EXCLUDED BECAUSE AN INTERFACE AND ITS IMPLEMENTATION NEED NOT
// AGREE ON THEM. TemplateServicer declares ApplyTemplate(..., userID string)
// and TemplateService implements it as ApplyTemplate(..., appliedBy string);
// a key rendered by types.TypeString carries both names, the two never met,
// and the walk reported the service as an entry nothing calls. The positive
// control below is what found it.
func methodKey(fn *types.Func) string {
	sig := fn.Type().(*types.Signature)
	tuple := func(t *types.Tuple) string {
		parts := make([]string, t.Len())
		for i := range parts {
			parts[i] = types.TypeString(t.At(i).Type(), nil)
		}
		return "(" + strings.Join(parts, ",") + ")"
	}
	return fmt.Sprintf("%s\x00%s%s variadic=%t", fn.Name(), tuple(sig.Params()), tuple(sig.Results()), sig.Variadic())
}

// pkgVarKey names a package-level variable across sessions, or "" for any
// other object.
func pkgVarKey(o types.Object) string {
	v, ok := o.(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
		return ""
	}
	return v.Pkg().Path() + "." + v.Name()
}

// isHandler reports whether a signature can serve an HTTP request: it takes
// an http.ResponseWriter and an *http.Request, in whatever position and among
// whatever else (HandleApplyTemplate also takes the template id).
func isHandler(sig *types.Signature) bool {
	var w, r bool
	for i := 0; i < sig.Params().Len(); i++ {
		switch types.TypeString(sig.Params().At(i).Type(), nil) {
		case "net/http.ResponseWriter":
			w = true
		case "*net/http.Request":
			r = true
		}
	}
	return w && r
}

// isFrozenWrite reports whether e is a string constant writing a frozen table.
func isFrozenWrite(info *types.Info, e ast.Expr) bool {
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String &&
		frozenWriteRE.MatchString(constant.StringVal(tv.Value))
}

// holdsFrozenWrite reports whether any constant inside e writes a frozen
// table: the string itself, or a map value, a slice element, a struct field.
func holdsFrozenWrite(info *types.Info, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && isFrozenWrite(info, x) {
			found = true
		}
		return !found
	})
	return found
}

// addPackage type-checks one package and adds its functions and edges.
func (g *callGraph) addPackage(fset *token.FileSet, imp types.Importer, importPath string, files []*ast.File) error {
	info := &types.Info{
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
		Types: map[ast.Expr]types.TypeAndValue{},
	}
	conf := types.Config{Importer: imp, Error: func(error) {}}
	pkg, err := conf.Check(importPath, fset, files, info)
	if err != nil {
		return err
	}
	g.indexTypes(pkg)

	posOf := func(p token.Pos) string {
		pp := fset.Position(p)
		return filepath.Base(filepath.Dir(pp.Filename)) + "/" + filepath.Base(pp.Filename) + ":" + fmt.Sprint(pp.Line)
	}

	// walk records edges from root into cur. executable says whether root is
	// code that RUNS - a function body - rather than a declaration's storage:
	// only running code can execute a statement, so only it can be a sink.
	var walk func(root ast.Node, cur string, executable bool)
	walk = func(root ast.Node, cur string, executable bool) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				// A HANDLER LITERAL IS AN ENTRY IN ITS OWN RIGHT - an inline
				// route registered in a setup function - so it gets its own
				// node and the setup function merely references it. Any other
				// literal (a WithOrgScope closure, a sort comparator) is part
				// of the function that holds it. Either way its body runs.
				into := cur
				if sig, ok := info.Types[x].Type.(*types.Signature); ok && isHandler(sig) {
					into = cur + "$handler@" + posOf(x.Pos())
					lit := g.node(into, posOf(x.Pos()))
					lit.handler = true
					g.node(cur, "").calls[into] = true
				}
				walk(x.Body, into, true)
				return false
			case ast.Expr:
				if executable && isFrozenWrite(info, x) {
					g.node(cur, "").sink = true
				}
				id, ok := x.(*ast.Ident)
				if !ok {
					return true
				}
				if key := pkgVarKey(info.Uses[id]); executable && key != "" {
					if g.varUses[cur] == nil {
						g.varUses[cur] = map[string]bool{}
					}
					g.varUses[cur][key] = true
				}
				fn, ok := info.Uses[id].(*types.Func)
				if !ok {
					return true
				}
				fn = fn.Origin()
				recv := fn.Type().(*types.Signature).Recv()
				if recv != nil && types.IsInterface(recv.Type()) {
					it := recv.Type().Underlying().(*types.Interface)
					set := make([]string, it.NumMethods())
					for i := range set {
						set[i] = methodKey(it.Method(i))
					}
					sort.Strings(set)
					u := ifaceUse{caller: cur, method: methodKey(fn), iface: set}
					g.pending[u.caller+"\x01"+u.method+"\x01"+strings.Join(set, "\x02")] = u
					return true
				}
				full := fn.FullName()
				me := g.node(cur, "")
				me.calls[full] = true
				if full == answerKey {
					me.answers = true
				}
				if full == refuseKey {
					me.refuses = true
				}
			}
			return true
		})
	}

	for _, f := range files {
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				obj, ok := info.Defs[decl.Name].(*types.Func)
				if !ok {
					continue
				}
				key := obj.FullName()
				n := g.node(key, posOf(decl.Pos()))
				if n.pos == "" {
					n.pos = posOf(decl.Pos())
				}
				if isHandler(obj.Type().(*types.Signature)) {
					n.handler = true
				}
				if decl.Body != nil {
					walk(decl.Body, key, true)
				}
			case *ast.GenDecl:
				// A variable's initialiser runs at load, from nowhere a caller
				// can name, so its edges belong to the package's init node; a
				// constant runs nothing. Neither is a sink by what it HOLDS -
				// the function that uses it is - but a function literal inside
				// an initialiser is code, and walk treats its body as such.
				if decl.Tok != token.VAR {
					continue
				}
				for _, spec := range decl.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, v := range vs.Values {
						if i < len(vs.Names) && holdsFrozenWrite(info, v) {
							if key := pkgVarKey(info.Defs[vs.Names[i]]); key != "" {
								g.sqlVars[key] = true
							}
						}
					}
				}
				walk(decl, importPath+".init", false)
			}
		}
	}
	return nil
}

// indexTypes records the pointer method set of every concrete named type the
// package declares. The POINTER set because it is the larger of the two: it
// holds every method either receiver can be called with, promoted ones
// included, so a type that implements an interface either way is found.
func (g *callGraph) indexTypes(pkg *types.Package) {
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || types.IsInterface(named) {
			continue
		}
		typeKey := types.TypeString(named, nil)
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < ms.Len(); i++ {
			fn, ok := ms.At(i).Obj().(*types.Func)
			if !ok {
				continue
			}
			mk := methodKey(fn)
			if g.methodsOf[typeKey] == nil {
				g.methodsOf[typeKey] = map[string]string{}
			}
			g.methodsOf[typeKey][mk] = fn.Origin().FullName()
			if g.typesWith[mk] == nil {
				g.typesWith[mk] = map[string]bool{}
			}
			g.typesWith[mk][typeKey] = true
		}
	}
}

// resolve completes the graph once every package is in it: each function that
// reads a variable holding a frozen write becomes a sink, and each
// interface-method reference becomes an edge to that method on every concrete
// type that implements the interface - whose method set holds every method the
// interface declares.
//
// IMPLEMENTATION, NOT NAME. The first version linked a call to every method
// with the same name and signature, and Delete(ctx, string, string) error is
// the signature of half the repositories in the tree: nine handlers calling
// their OWN repository's Delete through their own interface - RBI incidents,
// MAS FEAT systems, agent registrations - were reported as reaching the static
// policy table. Requiring the whole method set is the rule the Go type system
// applies, and it is what makes an unclassified handler here a real finding.
func (g *callGraph) resolve() {
	for fnKey, vars := range g.varUses {
		for v := range vars {
			if g.sqlVars[v] {
				g.node(fnKey, "").sink = true
				break
			}
		}
	}
	for _, u := range g.pending {
		for typeKey := range g.typesWith[u.method] {
			ms := g.methodsOf[typeKey]
			implements := true
			for _, m := range u.iface {
				if _, ok := ms[m]; !ok {
					implements = false
					break
				}
			}
			if implements {
				g.node(u.caller, "").calls[ms[u.method]] = true
			}
		}
	}
	g.pending = map[string]ifaceUse{}
}

// censusReport is what the upward walk found in one build.
type censusReport struct {
	sinks []string
	// handlers maps each handler reached to the sinks it reaches.
	handlers map[string][]string
	// entries maps each non-handler entry reached to the sinks it reaches.
	entries map[string][]string
}

// reach walks up from every sink.
func (g *callGraph) reach() censusReport {
	callers := map[string][]string{}
	for k, n := range g.nodes {
		for c := range n.calls {
			callers[c] = append(callers[c], k)
		}
	}
	rep := censusReport{handlers: map[string][]string{}, entries: map[string][]string{}}
	for k, n := range g.nodes {
		if n.sink {
			rep.sinks = append(rep.sinks, k)
		}
	}
	sort.Strings(rep.sinks)
	for _, s := range rep.sinks {
		seen := map[string]bool{s: true}
		queue := []string{s}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if n := g.nodes[cur]; n != nil && n.handler {
				rep.handlers[cur] = append(rep.handlers[cur], s)
				continue
			}
			up := callers[cur]
			if len(up) == 0 {
				rep.entries[cur] = append(rep.entries[cur], s)
				continue
			}
			for _, c := range up {
				if !seen[c] {
					seen[c] = true
					queue = append(queue, c)
				}
			}
		}
	}
	return rep
}

// classified reports whether a handler holds the freeze's answer: it calls
// Answer, or calls a function that does (every surface binds its own envelope
// in a one-line method, so the answer is one hop away, never deeper).
func (g *callGraph) classified(handler string) bool {
	n := g.nodes[handler]
	if n == nil {
		return false
	}
	if n.answers {
		return true
	}
	for c := range n.calls {
		if cn := g.nodes[c]; cn != nil && cn.answers && !cn.handler {
			return true
		}
	}
	return false
}

// refusesOverride reports whether a handler refuses a per-policy override
// write: it calls RefuseOverride, or a function that does, one hop away as
// classified allows for Answer.
func (g *callGraph) refusesOverride(handler string) bool {
	n := g.nodes[handler]
	if n == nil {
		return false
	}
	if n.refuses {
		return true
	}
	for c := range n.calls {
		if cn := g.nodes[c]; cn != nil && cn.refuses && !cn.handler {
			return true
		}
	}
	return false
}

// posOf is a node's position for a message, or "position unknown".
func (g *callGraph) posOf(key string) string {
	if n := g.nodes[key]; n != nil && n.pos != "" {
		return n.pos
	}
	return "position unknown"
}

// buildLabel names a tag set the way the messages do.
func buildLabel(tags string) string {
	if tags == "" {
		return "community build"
	}
	return tags + " build"
}

// censusResult is the whole program's census: each build judged on its own.
type censusResult struct {
	reports map[string]censusReport
	// unclassified are the handlers, per build, that reach a write and do not
	// answer - one message each.
	unclassified []string
	// entries maps each (entry, sink) pair any build reached to where it was
	// first seen.
	entries map[string]string
}

// evaluate walks every build's graph separately. A finding in one build is a
// finding, whatever another build holds for the same function.
func evaluate(graphs map[string]*callGraph) censusResult {
	res := censusResult{reports: map[string]censusReport{}, entries: map[string]string{}}
	for _, tags := range gocensus.TagSets {
		g, ok := graphs[tags]
		if !ok {
			continue
		}
		rep := g.reach()
		res.reports[tags] = rep
		for h, sinks := range rep.handlers {
			if !g.classified(h) {
				res.unclassified = append(res.unclassified, fmt.Sprintf("%s (%s, %s) reaches %s",
					h, g.posOf(h), buildLabel(tags), strings.Join(sinks, ", ")))
			}
		}
		for e, sinks := range rep.entries {
			for _, s := range sinks {
				if _, seen := res.entries[pairKey(e, s)]; !seen {
					res.entries[pairKey(e, s)] = fmt.Sprintf("%s, %s", g.posOf(e), buildLabel(tags))
				}
			}
		}
	}
	sort.Strings(res.unclassified)
	return res
}

// buildProgramGraphs loads every module in the census domain into one graph
// per build configuration, and reports which builds loaded the platform
// module itself.
func buildProgramGraphs(t *testing.T) (graphs map[string]*callGraph, platformIn map[string]bool) {
	t.Helper()
	root := gocensus.RepoRoot(t)
	// THE DOMAIN IS THE PLATFORM MODULE, EVERY MODULE THAT REQUIRES IT, AND
	// EVERY MODULE IT REPLACES WITH A LOCAL DIRECTORY. The first two are where a
	// handler can reach a platform write from; the third is code the platform
	// binaries compile in, where a write would reach a platform handler just as
	// surely. "Requires platform" does not cover what platform requires (R3
	// round two), so the locally replaced modules are read from go.mod rather
	// than listed here.
	targets := append([]string{platformModule}, localReplacements(t, filepath.Join(root, "platform", "go.mod"))...)
	modules := gocensus.DiscoverModules(t, root, targets...)
	for _, m := range targets {
		if _, ok := modules[m]; !ok {
			t.Fatalf("module %q was not discovered under %s; the census domain must hold the platform module and every module it replaces locally", m, root)
		}
	}
	t.Logf("census domain targets: %s", strings.Join(targets, ", "))
	unscannable := gocensus.Unscannable(modules)
	t.Logf("checkout shape: %s (%d module(s) in the census domain)", gocensus.CheckoutShape(modules), len(modules))

	graphs = map[string]*callGraph{}
	platformIn = map[string]bool{}
	for _, tags := range gocensus.TagSets {
		g := newCallGraph()
		loaded := 0
		for _, modPath := range gocensus.SortedKeys(modules) {
			pair := modPath + "|" + tags
			m, err := gocensus.Load(modules[modPath], tags)
			if err != nil {
				if reason, declared := unscannable[pair]; declared {
					t.Logf("not scanned: module %q under tags %q - %s", modPath, tags, reason)
					continue
				}
				t.Errorf("module %q could not be listed under tags %q, so a handler in it could reach a frozen write "+
					"unseen:\n%v", modPath, tags, err)
				continue
			}
			if _, declared := unscannable[pair]; declared {
				t.Errorf("module %q now lists under tags %q, so its unscannable row is stale", modPath, tags)
			}
			if modPath == platformModule {
				platformIn[tags] = true
			}
			for _, p := range m.Packages {
				if p.Error != nil {
					t.Errorf("%s (tags %q): go list: %s - a package this census cannot load is one it reports as clean",
						p.ImportPath, tags, p.Error.Err)
					continue
				}
				files, _, err := m.Parse(p.ImportPath, nil)
				if err != nil {
					t.Errorf("%s (tags %q): parse: %v", p.ImportPath, tags, err)
					continue
				}
				if len(files) == 0 {
					continue
				}
				if err := g.addPackage(m.Fset, m.Importer, p.ImportPath, files); err != nil {
					t.Errorf("%s (tags %q): type-check: %v - a package this census cannot type-check is one it reports as clean",
						p.ImportPath, tags, err)
					continue
				}
				loaded++
			}
		}
		if loaded == 0 {
			t.Logf("%s: no package loaded", buildLabel(tags))
			continue
		}
		g.resolve()
		graphs[tags] = g
	}
	// The community build of the platform module exists in every checkout
	// shape; a census that did not load it has looked at nothing that matters.
	if !platformIn[""] {
		t.Fatalf("the %s of %s was not loaded; the census has nothing to judge", buildLabel(""), platformModule)
	}
	return graphs, platformIn
}

// localReplacements returns the module path of every `replace X => ./dir` (or
// ../dir) in a go.mod: code the module compiles from this checkout. A local
// target with no go.mod, or one declaring a different module, is a failure -
// the replace would not build.
func localReplacements(t *testing.T, gomodPath string) []string {
	t.Helper()
	src, err := os.ReadFile(gomodPath)
	if err != nil {
		t.Fatalf("reading %s: %v", gomodPath, err)
	}
	var out []string
	inBlock := false
	for _, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "//", 2)[0])
		switch {
		case line == "replace (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "replace "):
			line = strings.TrimSpace(strings.TrimPrefix(line, "replace "))
		case !inBlock:
			continue
		}
		lhs, rhs, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}
		dir := strings.TrimSpace(rhs)
		if !strings.HasPrefix(dir, "./") && !strings.HasPrefix(dir, "../") {
			continue // a module-version replacement, not a local directory
		}
		want := strings.Fields(strings.TrimSpace(lhs))[0]
		sub, err := os.ReadFile(filepath.Join(filepath.Dir(gomodPath), dir, "go.mod"))
		if err != nil {
			t.Fatalf("%s replaces %s with %s, which has no go.mod: %v", gomodPath, want, dir, err)
		}
		got := ""
		for _, l := range strings.Split(string(sub), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "module "); ok {
				got = strings.TrimSpace(rest)
				break
			}
		}
		if got != want {
			t.Fatalf("%s replaces %s with %s, whose go.mod declares module %q", gomodPath, want, dir, got)
		}
		out = append(out, want)
	}
	sort.Strings(out)
	return out
}

// TestEveryHandlerReachingAFrozenWriteAnswersTheFreeze is the guard.
func TestEveryHandlerReachingAFrozenWriteAnswersTheFreeze(t *testing.T) {
	graphs, platformIn := buildProgramGraphs(t)
	// THE BUILDS ARE SEPARATE PROGRAMS, and a shared graph would union a
	// build-tag twin's flags with its sibling's. No such twin exists on this
	// path today, so nothing in the tree would red if the separation were
	// lost; this is the assertion that would.
	if gd, ge := graphs[""], graphs["enterprise"]; gd != nil && gd == ge {
		t.Fatal("the community and enterprise builds share one call graph; a build-tag twin that answers would vouch for one that does not")
	}
	res := evaluate(graphs)

	for _, tags := range gocensus.TagSets {
		rep, ok := res.reports[tags]
		if !ok {
			continue
		}
		t.Logf("%s: %d sink(s), %d handler(s) and %d other entr(ies) reached", buildLabel(tags), len(rep.sinks), len(rep.handlers), len(rep.entries))
		if !platformIn[tags] {
			continue
		}
		if len(rep.sinks) == 0 {
			t.Errorf("%s: no function writing a frozen table was found; the census is blind, not the tree clean - "+
				"core/172's own header names the write sites", buildLabel(tags))
		}
		// THE POSITIVE CONTROL, in every build that holds the platform module.
		for _, h := range expectedClassifiedHandlers {
			if _, reached := rep.handlers[h]; !reached {
				t.Errorf("%s: the walk did not reach %s from any sink. It is one of the surfaces this census was built "+
					"from; an instrument that cannot find a handler it is standing on cannot report the absence of one",
					buildLabel(tags), h)
			} else if !graphs[tags].classified(h) {
				t.Errorf("%s: %s is reached and does not answer the freeze", buildLabel(tags), h)
			}
		}
		// THE PER-POLICY OVERRIDE WRITERS, declared because no sink reaches them.
		for _, h := range overrideRefusers {
			switch n := graphs[tags].nodes[h]; {
			case n == nil:
				t.Errorf("%s: %s is not in the program; overrideRefusers is stale or the walk lost the agent", buildLabel(tags), h)
			case !n.handler:
				t.Errorf("%s: %s is not an HTTP handler", buildLabel(tags), h)
			case !graphs[tags].refusesOverride(h):
				t.Errorf("%s: %s does not refuse with legacyfreeze.RefuseOverride, so a per-policy override would be written; "+
					"v11 retired them (PRD v11 §1.5)", buildLabel(tags), h)
			}
		}
	}

	for _, u := range res.unclassified {
		t.Errorf("an HTTP handler reaches a write of a frozen table and does not answer the freeze: %s.\n"+
			"core/172 refuses that write for an application role, and without a call to legacyfreeze.Answer on "+
			"its error path the caller gets a bare 500 for a write path that was retired on purpose (#4084, #4088). "+
			"Route the error through a writeLegacyFreezeError bound to the handler's own error envelope.", u)
	}

	var unexplained []string
	for pair, where := range res.entries {
		if _, ok := nonHTTPEntries[pair]; !ok {
			unexplained = append(unexplained, fmt.Sprintf("%s (%s)", pair, where))
		}
	}
	sort.Strings(unexplained)
	for _, u := range unexplained {
		t.Errorf("an entry that is not an HTTP handler reaches a write of a frozen table: %s.\n"+
			"Either it is a customer surface - make it answer the freeze - or it is not, and the pair belongs in "+
			"nonHTTPEntries with the reason.", u)
	}
	for pair := range nonHTTPEntries {
		if _, reached := res.entries[pair]; !reached {
			t.Errorf("nonHTTPEntries lists %s, which no build reaches any more; the row is stale and must go", pair)
		}
	}

	// The population, printed, so a reviewer reads what was derived rather
	// than trusting that it was.
	for _, tags := range gocensus.TagSets {
		rep, ok := res.reports[tags]
		if !ok {
			continue
		}
		handlers := make([]string, 0, len(rep.handlers))
		for h := range rep.handlers {
			handlers = append(handlers, h)
		}
		sort.Strings(handlers)
		for _, h := range handlers {
			t.Logf("%s: handler %s (%s) classified=%t reaches %s", buildLabel(tags), h, graphs[tags].posOf(h),
				graphs[tags].classified(h), strings.Join(rep.handlers[h], ", "))
		}
		for _, s := range rep.sinks {
			t.Logf("%s: sink %s (%s)", buildLabel(tags), s, graphs[tags].posOf(s))
		}
	}
}
